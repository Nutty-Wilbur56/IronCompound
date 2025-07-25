# server.py
import json
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
from security.legionnaire import (
    load_blacklist, save_blacklist, check_token_status, blacklist_token, ReplayProtection, check_user_activity
)
from security.legionnaire import ips_manager
from security.legionnaire.ips_manager import LegionnaireManager, SecurityRule
from security.legionnaire import legionnaire_rules
from security.legionnaire.throttling.throttling_manager import ThrottleManager
from administration.gulag_manager import GulagManager

#import geoip2.database as gip2

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

inactivity = 1000
# Inactivity serves as monitor for clients whose activity on the server is very low

"""Beginning of global thread lock variables"""
active_clients = 0
client_lock = threading.Lock()
# establishment of client lock

session_tokens = {}
session_lock = threading.Lock()
# establishment of both session lock and session token dictionary

client_sockets_dict = {}
client_socket_lock = threading.Lock()
# establishment of dictionary that will store socket info of each client
# establishment of lock for client sockets

SCHINDLERS_LIST = "gulag.json"
gulag_tokens = set()
gulag_lock = threading.Lock()
# gugaga tokens consist of all the session tokens that were utilized to violate or breach the server
"""Ending of global thread lock variables"""

# nation_reader = gip2.Reader('GeoLite2-City.mmdb')
# establishment of reader variable that will be able to pull client's nation from IP range
# will be utilized in the later stages of development

# configuring logging system for vpn server
logging.basicConfig(
    filename='iron_server.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)

# beginning of logic for creating timeout log
timeout_logger = ('timeout.log')
timeout_lock = logging.getLogger("timeout_logger")
timeout_handler = logging.FileHandler(timeout_logger)
timeout_handler.setFormatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
timeout_logger.addHandler(timeout_handler)
timeout_logger.setLevel(logging.INFO)
# ending of timeout log logic

# Set up main server logger
logger = logging.getLogger("vpn")
logger.setLevel(logging.INFO)

# Log rotation: max 1MB per file, keep 5 backups
handler = RotatingFileHandler("vpn_server.log", maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(handler)

client_counter = count(1)

ADMINISTRATIVE_SOCK = 'administration/iron_admin.sock'
# not using actual name of sock file, since code will be public on github

"""beginning of IPS creation"""
# global instance of ips manager class
legionnaire_ips = LegionnaireManager()

# loading of the legionnaire's rules all at once
for rule in legionnaire_rules.get_legions_rules():
    legionnaire_ips.add_rule(rule)
"""Ending of IPS creation"""

replay_protection = ReplayProtection()

# RULE: Kick clients inactive more than 10 mins
def inactivity_exceeded(session):
    return time.time() - session.get("last_activity", 0) > 600

def disconnect_inactive_client(session, client_id):
    logging.warning(f"[IPS] Client {client_id} flagged for inactivity. Disconnect requested.")
    session["flagged_for_disconnect"] = True


# RULE: Blacklist clients with > 5 replay attempts
def excessive_replay_attempts(session):
    return session.get("replay_hits", 0) > 5

def blacklist_client(session, client_id):
    #session["flagged_for_blacklist"] = True
    logging.warning(f"[IPS] Client {client_id} flagged for blacklisting.")

legionnaire_ips.add_rule(SecurityRule("Inactivity Disconnect", inactivity_exceeded, disconnect_inactive_client))
legionnaire_ips.add_rule(SecurityRule("Replay Threshold Blacklist", excessive_replay_attempts, blacklist_client))

def load_schindlers_list():
    # function handles blacklisted tokens
    global gulag_tokens
    if os.path.exists(SCHINDLERS_LIST):
        with open(SCHINDLERS_LIST, 'r') as file:
            tokens = json.load(file)
            with gulag_lock:
                gulag_tokens = set(tokens)
        logging.info("[+] Loaded blacklist from file.")

def administrative_command_interface():
    # interface for managing client connections
    if os.path.exists(ADMINISTRATIVE_SOCK):
        os.unlink(ADMINISTRATIVE_SOCK)

    iron_serve = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    iron_serve.bind(ADMINISTRATIVE_SOCK)
    iron_serve.listen(1)
    os.chmod(ADMINISTRATIVE_SOCK, 0o600)

    print("[+] Admin socket listening")

    while True:
        connection, _ = iron_serve.accept()

        with connection:
            try:
                command = connection.recv(1024).decode().strip()
                response = socket_admin_handler(command)

                connection.sendall(response.encode())

            except Exception as e:
                connection.sendall(f"[!] Admin command error {e}".encode())

def socket_admin_handler(command):
    # function responsible for handling commands issued by the administrative command interface
    if command == 'list sessions':
        # if statement lists the current sessions
        with session_lock:
            lines = []

            for cid, info in session_tokens.items():
                uptime = time.time() - info['start_time']
                lines.append(
                    f"Client {cid} | IP: {info['ip']} | Token: {info['token']} | Uptime: {uptime:.1f}s"
                )
            return "\n".join(lines) or "No active sessions"

    elif command.startswith('kill '):
        # if statement kills a singled out client session
        try:
            cid = int(command.split()[1])
            with client_socket_lock:
                client_socket = client_sockets_dict.get(cid)

                if client_socket:
                    client_socket.shutdown(socket.SHUT_RDWR)
                    client_socket.close()

                    return f"[+] Client {cid} connection terminated."
                else:
                    return f"[!] Client {cid} not found."
        except Exception as e:
            return f"[!] Client {cid} was not found"

    elif command.startswith("revoke token "):
        # action to revoke token of session and add to token blacklist.
        token = command.split()[1]
        with gulag_lock:
            gulag_tokens.add(token)
            with open(SCHINDLERS_LIST, 'w') as f:
                json.dump(list(gulag_tokens), f)
        return f"[+] Token {token} has been blacklisted and saved."

    elif command == "help":
        return (
            "Commands for you comrade\n"
            "- list_sessions\n"
            "- kill <client_id>\n"
            "- revoke_token <token>\n"
            "- help"
        )
    else:
        return "[!] Comrade, you have issued an unknown command. Type 'help'."

def save_client_sessions():
    # enables vpn server to save client sessions, if server were to restart
    with session_lock:
        with open('session_tokens', 'w') as session_file:
            json.dump(session_tokens, session_file)

def load_client_sessions():
    # load client sessions from disk, when server restarts (if need be)
    global session_tokens
    try:
        with open('session_tokens', 'r') as session_file:
            session_tokens = json.load(session_file)
    except FileNotFoundError:
        session_tokens = {}


"""def flush_iptables():
    # flushing ip tables
    # function will force server to flush all IP tables, if server is ever shutdown and reactivated
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
        print(f"[!] Error flushing iptables: {e}")"""

def create_tun(name):
    tun = os.open('/dev/net/tun', os.O_RDWR)
    # tunnel being opened is going to contain fake reference and name for security purposes
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

"""def periodical_session_logging():
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
        time.sleep(1800)"""

def handle_client(client_socket, addr, client_id):
    global active_clients
    global inactivity
    start_time = time.time()

    tun_name = f"tun{client_id}"
    tun_ip = f"10.8.0.{client_id + 1}"
    # consider
    tun = create_tun(tun_name)
    set_up_tun(tun_name, tun_ip)

    # Replay protection structures
    recent_nonces = set()
    nonce_queue = deque(maxlen=1000)

    try:
        with client_lock:
            # prevention of race conditions when incrementing or decrementing the shared counter
            active_clients += 1
            logging.info(f"[Client {client_id}] Connected from {addr[0]} | Active clients: {active_clients}")

        with client_socket_lock:
            # prevents race conditions when accessing shared socket map
            client_sockets_dict[client_id] = client_socket

        # beginning of authentication and tunnel logic
        logging.info(f"Client connected from {addr} assigned to {tun_name}")

        # Loading of trusted client public key
        with open('authorized_clients/iron_client_public.pem', 'rb') as f:
            trusted_client_key = serialization.load_pem_public_key(f.read())

        # Receival and parsing of received key
        client_public_key_bytes = client_socket.recv(2048)
        received_client_key = serialization.load_pem_public_key(client_public_key_bytes)

        # Verification of key fingerprint
        if public_key_fingerprint(trusted_client_key) != public_key_fingerprint(received_client_key):
            logging.error("[!] Client public key does not match trusted key! Connection rejected.")
            client_socket.close()
            return

        client_public_key = received_client_key  # Verified client key
        logging.info("[+] Client public key verified successfully")

        # Generate and send server key
        server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_public_key = server_private_key.public_key()
        client_socket.sendall(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Receiving and decryption of AES key
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

        with gulag_lock:
            # checking gulag lock oon specific client thread
            if token in gulag_tokens:
                # logic for if client's token is blacklisted
                logging.warning(f"[!] Blacklisted token {token} attempted to connect from {addr}")

                try:
                    client_socket.sendall(b"Your token is blacklisted. Connection refused.")
                except:
                    pass
                client_socket.close()

        fingerprint = public_key_fingerprint(client_public_key).hex()

        with session_lock:
            # adding a session token once client and server are authenticated
            session_tokens[client_id] = {
                'client_id': client_id,
                "token": token,
                "ip": addr[0],
                'fingerprint': fingerprint,
                "start_time": start_time,
                "bytes_sent": 0,
                "bytes_received": 0,
                "violations": {
                    "Throttling Violation": 0,
                    "Replay Violation": 0,
                    "Flooding Violation": 0,
                },
                'client warned': False,
                "flagged_for_disconnect": False
            }


        logging.info(f"[Client {client_id}] Session token: {token}]")

        # Tunnel communication loop
        while True:
            with session_lock:
                session = session_tokens[client_id]
                legionnaire_ips.evaluate_session(session, client_id)
                # legionnaire IPS evaluates each client session

                if session.get('flagged_for_disconnect'):
                    logging.info(f"[Client {client_id}] past infractions triggered disconnect")
                    timeout_logger.info(f"Client {client_id} ({addr[0]}) disconnected due to past infractions.")

                    try:
                        # beginning of client removal
                        client_disconnect = b"Due to past infractions you are being removed from the server"
                        nonce = os.urandom(12)
                        encrypted_disconnect = nonce + aes.encrypt(nonce, client_disconnect, None)
                        client_socket.sendall(encrypted_disconnect)
                        # ending of removal
                    except Exception as e:
                        logging.warning(f'Failed to send disconnect message: {e}')

                    # logging session info of client that is being removed
                    session_info = {
                        'client_id': client_id,
                        "ip": addr[0],
                        "fingerprint": fingerprint,
                        'token': token,
                        "bytes_sent": session_tokens[client_id]["bytes_sent"],
                        "start_time": session_tokens[client_id]["start_time"],
                        "end_time": time.time(),
                        'duration': time.time() - session_tokens[client_id]["start_time"],
                        "reason_for_disconnection": "past infraction"
                    }

                    with open('session_logs.json', 'a') as disconnection_file:
                        disconnection_file.write(json.dumps(session_info) + '\n')

                    client_sockets_dict.pop(client_id, None)
                    session_tokens.pop(client_id)
                    client_socket.close()
                    break

            r, _, _ = select.select([client_socket, tun], [], [])
            if client_socket in r:
                data = client_socket.recv(4096)
                if not data:
                    break
                nonce = data[:12]
                ciphertext = data[12:]

                if replay_protection.existing_nonce(nonce):
                    # checking to see if nonce that packet generated already exists
                    logging.warning(f"[!] Replay attack detected from {addr}. dropping packet.")
                    continue

                replay_protection.register_nonce(nonce)

                # track incoming encrypted packet size for throttling
                ThrottleManager.record_transfer(client_id, len(ciphertext))

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

                with session_lock:
                    # update on each token in session lock
                    session_tokens[client_id]["bytes_sent"] += len(packet)
                    session_tokens[client_id]["last_activity"] = time.time()

                os.write(tun, packet)

                if tun in r:
                    packet = os.read(tun, 2048)
                    nonce = os.urandom(12)
                    encrypted = nonce + aes.encrypt(nonce, packet, None)

                    with session_lock:
                        # documenting when client receives a packet from server during session
                        session_tokens[client_id]["bytes_received"] += len(packet)
                        session_tokens[client_id]["last_activity"] = time.time()

                    # Tracking of outgoing cleartext payload size
                    ThrottleManager.record_transfer(client_id, len(packet))
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

        with client_socket_lock:
            # removing client socket info of client that disconnected from client socket dictionary
            client_sockets_dict.pop(client_id)

def vpn_server(host='0.0.0.0', port=1871):
    # utilizing fake ip and fake port for security purposes
    print("[+] Initializing VPN server...")

    # establishment of server socket
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    logging.info(f"VPN server listening on {host}:{port}")

    # persistant token black list (enables a permanent token blacklist)
    try:
        with open('administration/gulag.json', "r") as gulag_file:
            gulag_tokens = set(json.load(gulag_file))
    except FileNotFoundError:
        gulag_tokens = set()

    with ThreadPoolExecutor(max_workers=25) as executor:
        threading.Thread(target=administrative_command_interface, daemon=True).start()
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
