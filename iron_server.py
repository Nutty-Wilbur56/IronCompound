# server.py
import os, socket, fcntl, struct, select, subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
import threading
from itertools import count
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from collections import deque
import time
import uuid
#import geoip2.database as gip2

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000
active_clients = 0
client_lock = threading.Lock()
# establishment of client lock

session_tokens = {}
session_lock = threading.Lock()
# establishment of both session lock and session token dictionary

# nation_reader = gip2.Reader('GeoLite2-City.mmdb')
# establishment of reader variable that will be able to pull client's nation from IP range
# will be utilized in the later stages of development

# configuring logging system
logging.basicConfig(
    filename='iron_server.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)

# Set up logger
logger = logging.getLogger("vpn")
logger.setLevel(logging.INFO)

# Log rotation: max 1MB per file, keep 5 backups
handler = RotatingFileHandler("vpn_server.log", maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(handler)

client_counter = count(1)

def flush_iptables():
    # flushing ip tables
    try:
        # Flush all chains in filter table
        subprocess.run(["iptables", "-F"], check=True)
        # Delete all user-defined chains
        subprocess.run(["iptables", "-X"], check=True)
        # Flush NAT table
        subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
        subprocess.run(["iptables", "-t", "nat", "-X"], check=True)
        # Flush mangle table (optional)
        subprocess.run(["iptables", "-t", "mangle", "-F"], check=True)
        subprocess.run(["iptables", "-t", "mangle", "-X"], check=True)
        # Zero counters
        subprocess.run(["iptables", "-Z"], check=True)

        print("[+] iptables rules flushed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error flushing iptables: {e}")

def create_tun(name='tun0'):
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

def set_up_tun(name, ip):
    subprocess.run(['ip', 'addr', 'add', f'{ip}/24', 'dev', name])
    subprocess.run(['ip', 'link', 'set', name, 'up'])

def is_client_authorized(client_public_key):
    for filename in os.listdir('/authorized'):
        # not actual directory name...not going to store the actual name on github for security purposes
        path = os.path.join('/authorized', filename)
        with open(path, 'rb') as f:
            allowed_public_key = serialization.load_pem_public_key(f.read())
            if client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) == allowed_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                return True
    return False

# Step 3: Compare fingerprints
def public_key_fingerprint(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def periodical_session_logging():
    # function logs all sessions that are live every 30 minutes
    # future plans for session logging
    # 1.(ability to query and kill active sessions)
    # 2. Blacklist tokens
    # 3. tying of tokens to encrypted session keys
    while True:
        with session_lock:
            for cid, info in session_tokens.items():
                uptime = time.time() - info["start_time"]
                logging.info(
                    f"[Session Monitor] Client {cid} | IP: {info['ip']} | "
                    f"Token: {info['token']} | Uptime: {uptime:.1f}s"
                )
        time.sleep(1800)

def handle_client(client_socket, addr, client_id):
    global active_clients
    start_time = time.time()

    with client_lock:
        active_clients += 1
        logging.info(f"[Client {client_id}] Connected from {addr[0]} | Active clients: {active_clients}")

    tun_name = f"tun{client_id}"
    tun_ip = f"10.8.0.{client_id + 1}"
    # consider
    tun = create_tun(tun_name)
    set_up_tun(tun_name, tun_ip)

    # Replay protection structures
    recent_nonces = set()
    nonce_queue = deque(maxlen=1000)

    try:
        # beginning of authentication and tunnel logic
        logging.info(f"Client connected from {addr} assigned to {tun_name}")

        # Step 1: Load trusted client public key
        with open('random_public_key', 'rb') as f:
            # key name is not the actual name of key in reality
            trusted_client_key = serialization.load_pem_public_key(f.read())

        # Step 2: Receive and parse received key
        client_public_key_bytes = client_socket.recv(2048)
        received_client_key = serialization.load_pem_public_key(client_public_key_bytes)

        # Step 3: Verify fingerprint
        if public_key_fingerprint(trusted_client_key) != public_key_fingerprint(received_client_key):
            logging.error("[!] Client public key does not match trusted key! Connection rejected.")
            client_socket.close()
            return

        client_public_key = received_client_key  # Verified client key
        logging.info("[+] Client public key verified successfully")

        # Step 4: Generate and send server key
        server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_public_key = server_private_key.public_key()
        client_socket.sendall(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Step 5: Receive and decrypt AES key
        encrypted_key = client_socket.recv(4096)
        aes_key = server_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes = AESGCM(aes_key)
        logging.info(f"[+] AES key exchange complete with {addr}")

        token = uuid.uuid1().hex

        with session_lock:
            # adding a session token once client and server are authenticated
            session_tokens[client_id] = {
                "token": token,
                "ip": addr[0],
                "start_time": start_time
            }

        logging.info(f"[Client {client_id}] Session token: {token}]")

        # Tunnel communication loop
        while True:
            r, _, _ = select.select([client_socket, tun], [], [])
            if client_socket in r:
                data = client_socket.recv(4096)
                if not data:
                    break
                nonce = data[:12]
                ciphertext = data[12:]

                if nonce in recent_nonces:
                    logging.warning(f"[!] Replay attack detected from {addr}. Dropping packet.")
                    continue  # Drop duplicate packet

                try:
                    packet = aes.decrypt(nonce, ciphertext, None)
                except Exception as e:
                    logging.error(f"[!] Decryption error with {addr}: {e}")
                    continue

                # If decryption is successful, now update nonce tracking
                if len(nonce_queue) == nonce_queue.maxlen:
                    recent_nonces.discard(nonce_queue.popleft())

                nonce_queue.append(nonce)
                recent_nonces.add(nonce)

                os.write(tun, packet)

            if tun in r:
                packet = os.read(tun, 2048)
                nonce = os.urandom(12)
                encrypted = nonce + aes.encrypt(nonce, packet, None)
                client_socket.sendall(encrypted)
        # ending to tunnel and authentication logic
    except Exception as e:
        logging.error(f"[!] Exception with client {addr}: {e}", exc_info=True)
    finally:
        logging.info(f"[-] Connection closed from {addr}")
        client_socket.close()
        os.close(tun)
        session_uptime = time.time() - start_time

        with client_lock:
            # removing a client from client lock after client disconnects from server
            active_clients -= 1
            logging.info(
                f"[Client {client_id}] Disconnected from {addr[0]} | \n"
                f"Uptime: {session_uptime:.2f}s | Active clients: {active_clients}"
            )

        with session_lock:
            # removing session token
            if client_id in session_tokens:
                del session_tokens[client_id]


def vpn_server(host='0.0.0.0', port=1871):
    print("[+] Initializing VPN server...")

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    logging.info(f"VPN server listening on {host}:{port}")

    with ThreadPoolExecutor(max_workers=25) as executor:
        while True:
            try:
                client_socket, addr = server_socket.accept()
                client_id = next(client_counter)
                logging.info(f"[Client {client_id}] Connected from {addr}")
                executor.submit(handle_client, client_socket, addr, client_id)
                #threading.Thread(target=periodical_session_logging, daemon=True).start()
            except Exception as e:
                logging.error(f"[!] Server accept error: {e}")

if __name__ == "__main__":
    vpn_server()
