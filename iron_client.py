# file serves as a pseudo client
# as of right now my router serves both purposes of client and server
from collections import deque
import os
import socket
import fcntl
import struct
import select
import subprocess
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import vpn_logging
import time

from vpn_logging.server_logs.server_log import IronLog

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

vpn_logging.basicConfig(
    filename='vpn_client.log',
    level=vpn_logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def create_tun(name='tun1'):
    # establishes separate tunnel for client
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    return tun

def set_up_tun(name, ip):
    # function sets up tunnel for client on the router
    subprocess.run(['ip', 'addr', 'add', f'{ip}/24', 'dev', name])
    subprocess.run(['ip', 'link', 'set', name, 'up'])

def add_default_route():
    subprocess.run(['ip', 'route', 'add', 'default', 'dev', 'tun1'])

def load_private_key(path='client_private.pem'):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def public_key_fingerprint(pubkey):
    # returns the public key in order to compare the fingerprints
    return pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def vpn_client(server_ip='192.168.8.1', port=1871):
    # using fake ip and fake port for security purposes
    # main function that handles pseudo vpn Client
    print("[+] Starting VPN client...")
    # Store recent nonces to avoid replay attacks
    recent_nonces = set()
    nonce_queue = deque(maxlen=1000)  # limit memory

    tun = create_tun('tun1')
    set_up_tun('tun1', '10.8.0.2')
    # not going to cover this up, since the client file is servign as a sudo file
    add_default_route()

    private_key = load_private_key('iron_server_public.pem')
    # client's private key: using a fake name, since code is going to be public on GitHub
    public_key = private_key.public_key()
    # client's public key

    sock = socket.socket()
    sock.connect((server_ip, port))
    # creation of socket
    IronLog.info(f"Connected to VPN server at {server_ip}:{port}")

    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.send(pubkey_bytes)


    # loads in the trusted public key of VPN server
    with open("fake server public key", 'rb') as f:
        # using fake server public key for security purposes
        trusted_server_key = serialization.load_pem_public_key(f.read())

    # receiving of server key and then parsing of key
    server_public_key_bytes = sock.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Comparing fingerprints of received server key and actual public server jey
    if public_key_fingerprint(trusted_server_key) != public_key_fingerprint(server_public_key):
        vpn_logging.error("[!] Server public key does not match trusted key! Possible MITM.")
        sock.close()
        exit(1)

    # server public key has been identified
    official_server_key = server_public_key
    vpn_logging.info("[+] Server public key verified successfully")

    # loading of client's saved token and/or starting of new session
    try:
        with open('client_token.txt', 'r') as client_token_file:
            client_token = client_token_file.read().strip()
            vpn_logging.info(f'[+] Loaded existing session token: {client_token}')
    except FileNotFoundError:
        client_token = 'New'
        vpn_logging.info('[+] No existing token for client was found, requesting new session')

    sock.sendall(client_token.encode() + b"\n")

    aes_key = os.urandom(32)
    enc_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # ecryption of keys
    sock.send(enc_key)

    aes = AESGCM(aes_key)
    vpn_logging.info("AES key exchanged")

    # beginning of new session token
    if client_token == 'New':
        token_response = sock.recv(2048).decode().strip()

        if token_response.startswith("Token: "):
            new_client_token = token_response.split("Token: ")[1]
            with open('client_token.txt', 'w') as token_file:
                token_file.write(new_client_token)

            vpn_logging.info(f'[+] Received and saved new session token: {new_client_token}')

        else:
            vpn_logging.warning(f'[!] Unexpected token response from server: {token_response}')
    # ending to generating new session token

    while True:
        # transfer of packets occurs in this loop
        r, _, _ = select.select([tun, sock], [], [])
        if tun in r:
            packet = os.read(tun, 2048)
            nonce = os.urandom(12)
            encrypted_packet = nonce + aes.encrypt(nonce, packet, None)
            sock.sendall(encrypted_packet)

            stored_packet = encrypted_packet
            time.sleep(1)
            sock.sendall(stored_packet)

        if sock in r:
            data = sock.recv(4096)
            if not data:
                break
            nonce = data[:12]
            ciphertext = data[12:]
            try:
                if nonce in recent_nonces:
                    vpn_logging.warning("Replay attack detected: repeated nonce!")
                    continue  # or break, depending on severity
                recent_nonces.add(nonce)
                nonce_queue.append(nonce)
                packet = aes.decrypt(nonce, ciphertext, None)

                if len(nonce_queue) == nonce_queue.maxlen:
                    recent_nonces.discard(nonce_queue.popleft())
                nonce_queue.append(nonce)
                recent_nonces.add(nonce)
                os.write(tun, packet)
            except Exception as e:
                vpn_logging.error(f"Decryption error: {e}")

if __name__ == "__main__":
    vpn_client()
