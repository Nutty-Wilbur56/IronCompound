# server.py
import json
import os, socket, fcntl, struct, select, subprocess
from datetime import datetime

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
import threading
from itertools import count
from administration.logging.server_logs.server_log import IronLog
from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from concurrent.futures import ThreadPoolExecutor
from collections import deque
import time
import uuid
from security.legionnaire import (
    ReplayProtection
)
from security.legionnaire.ips_manager import LegionnaireManager
from security.legionnaire.throttling.throttling_manager import ThrottleManager
from security.legionnaire.violation_management import ViolationManager
from security.session_tracking.sess_track import SessionTracker

"""
integrate the following code into the server loop 

is_flagged = IronSessionClassifier.classify_session(session)
if is_flagged:
    ViolationManager.record_violation(session, "Model Classifier Flag", session.client_id)
    logging.warning(f"[IPS] Session {session.client_id} flagged by model classifier."
"""

# import geoip2.database as gip2

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

gulag_lock = threading.Lock()
client_lock = threading.Lock()
client_socket_lock = threading.Lock()
session_lock = threading.Lock()
client_sockets_dict = {}
# nation_reader = gip2.Reader('GeoLite2-City.mmdb')
# establishment of reader variable that will be able to pull client's nation from IP range
# will be utilized in the later stages of development

client_counter = count(1)

ADMINISTRATIVE_SOCK = 'administration/iron_admin.sock'
# not using actual name of sock file, since code will be public on github

"""beginning of IPS/rules creation"""
# global instance of ips manager class
legionnaire_ips = LegionnaireManager()

"""Ending of IPS creation"""

replay_protection = ReplayProtection()


def load_schindlers_list():
    # function handles blacklisted tokens
    # move code to IPS
    global gulag_tokens
    if os.path.exists(SCHINDLERS_LIST):
        with open(SCHINDLERS_LIST, 'r') as file:
            tokens = json.load(file)
            with gulag_lock:
                gulag_tokens = set(tokens)
        logging.info("[+] Loaded blacklist from file.")


def administrative_command_interface():
    # interface for managing client connections
    # move code to administration
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
    # move code to IPS somehow
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


def handle_client(client_socket, addr, client_id):
    global active_clients
    start_time = time.time()

    with gulag_lock:
        # also gulag lock will be based upon ip address, not tokens
        if legionnaire_ips.check_if_client_in_gulag(addr[0]):
            LegionnaireLogger.log_legionnaire_activity(f"Connection attempt made by blacklisted IP: {addr[0]}")
            return

    tun_name = f"tun{client_id}"
    tun_ip = f"10.8.0.{client_id + 1}"
    # creation of tunnel variables
    tun = create_tun(tun_name)
    set_up_tun(tun_name, tun_ip)

    # Replay protection structures
    recent_nonces = set()
    nonce_queue = deque(maxlen=1000)

    try:
        with client_lock:
            # prevention of race conditions when incrementing or decrementing the shared counter
            active_clients += 1
            IronLog.log_server_activity(
                f"[Client {client_id}] attempting connection from {addr[0]} | Active clients: {active_clients}")

        # Loading of trusted client public key
        with open('authorized_clients/iron_client_public.pem', 'rb') as f:
            trusted_client_key = serialization.load_pem_public_key(f.read())

        # Receival and parsing of received key
        client_public_key_bytes = client_socket.recv(2048)
        received_client_key = serialization.load_pem_public_key(client_public_key_bytes)

        # Verification of key fingerprint
        if public_key_fingerprint(trusted_client_key) != public_key_fingerprint(received_client_key):
            IronLog.log_server_activity(
                f"[!] Client public key from address {addr[0]} does not match trusted key! Connection rejected")
            client_socket.close()
            return

        client_public_key = received_client_key  # Verified client key
        IronLog.log_server_activity(f"[+] Client public key from {addr[0]} verified successfully")

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
        IronLog.log_server_activity(f"[+] AES key exchange complete with {addr}")

        token = uuid.uuid1().hex

        fingerprint = public_key_fingerprint(client_public_key).hex()

        with session_lock:
            # session lock to prevent race conditions
            # session tracker logic
            SessionTracker.session_creation(
                client_id=client_id,
                ip_address=tun_ip,
                tunnel=tun_name,
                connection_time=datetime.now(),
                disconnection_time=None,
                last_activity=datetime.now(),
                initial_ip=addr[0],
                token=token,
                client_socket=client_socket,
                client_fingerprint=fingerprint,
                bytes_received=0,
                bytes_sent=0,
                client_violations={
                    "SYN Flooding Violations": 0,
                    "ICMP Flooding Violations": 0,
                    "Throttling Violations": 0,
                    "Replay Violations": 0
                },
                client_inactivity_warned = False,
                flagged_for_disconnect=False,
                flagged_for_blacklist=False
            )

        IronLog.log_server_activity(
            f"[Client {client_id}], tunnel_ip: {tun_ip} tunnel:{tun_name} Session token: {token}]")
        legionnaire_ips.start_packet_sniffers(client_id, None)
        # Tunnel communication loop
        while True:
            with session_lock:
                #legionnaire_ips.evaluate_session(session, client_id)
                # legionnaire IPS evaluates each client session

                if legionnaire_ips.evaluate_session(client_id):

                    try:
                        # beginning of client removal
                        client_disconnect = (b"Due to infractions against our policies,"
                                             b" you are being removed from the server")
                        nonce = os.urandom(12)
                        encrypted_disconnect = nonce + aes.encrypt(nonce, client_disconnect, None)
                        client_socket.sendall(encrypted_disconnect)
                        # ending of removal
                    except Exception as e:
                        LegionnaireLogger.log_legionnaire_activity(f'Failed to send disconnect message: {e} to client {addr[0]}')

                    with open('../../session_logs/session_logs.json', 'a') as disconnection_file:
                        disconnection_file.write(json.dumps({client_id:
                                                             SessionTracker.client_sessions[client_id]}) + '\n')

                    SessionTracker.client_sessions[client_id]["disconnection_time"] = datetime.now()
                    SessionTracker.end_session(client_id)
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
                    LegionnaireLogger.log_legionnaire_activity(f"[!] Replay attack detected from {addr} at {datetime.now()}. dropping packet.")
                    ViolationManager.record_violation("Replay Violation", client_id)
                    continue

                replay_protection.register_nonce(nonce)

                # track incoming encrypted packet size for throttling
                ThrottleManager.record_transfer(client_id, len(ciphertext))

                try:
                    packet = aes.decrypt(nonce, ciphertext, None)
                except Exception as e:
                    LegionnaireLogger.log_legionnaire_activity(f"[!] Decryption error with {addr}: {e}")
                    continue

                # If decryption is successful, now update nonce tracking
                if len(nonce_queue) == nonce_queue.maxlen:
                    recent_nonces.discard(nonce_queue.popleft())

                nonce_queue.append(nonce)
                recent_nonces.add(nonce)

                with session_lock:
                    # update on each token in session lock
                    SessionTracker.client_sessions[client_id]["bytes_sent"] += len(packet)
                    SessionTracker.client_sessions[client_id]["last_activity"] = datetime.now()

                os.write(tun, packet)

                if tun in r:
                    packet = os.read(tun, 2048)
                    nonce = os.urandom(12)
                    encrypted = nonce + aes.encrypt(nonce, packet, None)

                    with session_lock:
                        # documenting when client receives a packet from server during session
                        SessionTracker.client_sessions[client_id]["bytes_received"] += len(packet)
                        SessionTracker.client_sessions[client_id]["last_activity"] = datetime.now()

                    # Tracking of outgoing cleartext payload size
                    """ThrottleManager.record_transfer(client_id, len(packet))"""
                    client_socket.sendall(encrypted)

                    legionnaire_ips.evaluate_session(client_id)

        # ending to tunnel and authentication logic
    except Exception as e:
        LegionnaireLogger.log_legionnaire_activity(f"[!] Exception with client {addr}: {e}")
    finally:
        IronLog.log_server_activity(f"[-] Connection closed from {addr}")
        client_socket.close()
        os.close(tun)
        session_uptime = time.time() - start_time

        with client_lock:
            # removing a client from client lock after client disconnects from server
            active_clients -= 1
            IronLog.log_server_activity(
                f"[Client {client_id}] Disconnected from {addr[0]} | \n"
                f"Uptime: {session_uptime:.2f}s | Active clients: {active_clients}"
            )

def vpn_server(host='0.0.0.0', port=1871):
    # utilizing fake ip and fake port for security purposes
    print("[+] Initializing VPN server...")

    # establishment of server socket
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen()
    IronLog.log_server_activity(f"VPN server listening on {host}:{port}")

    """# persistant token black list (enables a permanent token blacklist)
    try:
        with open('security/gulag/gulag.json', "r") as gulag_file:
            gulag_tokens = set(json.load(gulag_file))
    except FileNotFoundError:
        gulag_tokens = set()"""

    with ThreadPoolExecutor(max_workers=25) as executor:
        # threading.Thread(target=administrative_command_interface, daemon=True).start()
        while True:
            try:
                client_socket, addr = server_socket.accept()
                client_id = next(client_counter)
                IronLog.log_server_activity(f"[Client {client_id}] Connected from {addr}")
                executor.submit(handle_client, client_socket, addr, client_id)
                # threading.Thread(target=periodical_session_logging, daemon=True).start()
            except Exception as e:
                IronLog.log_server_activity(f"[!] Server accept error: {e}")

if __name__ == "__main__":
    vpn_server()
