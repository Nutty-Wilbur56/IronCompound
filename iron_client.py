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
import logging
import time

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

logging.basicConfig(
    filename='vpn_client.log',
    level=logging.INFO,
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
    print("[+] Starting VPN client...")
    # Store recent nonces to avoid replay attacks
    recent_nonces = set()
    nonce_queue = deque(maxlen=1000)  # limit memory

    tun = create_tun('tun1')
    set_up_tun('tun1', '10.8.0.2')
    add_default_route()

    private_key = load_private_key('iron_client_private.pem')
    public_key = private_key.public_key()

    sock = socket.socket()
    sock.connect((server_ip, port))
    logging.info(f"Connected to VPN server at {server_ip}:{port}")

    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.send(pubkey_bytes)

    """server_pubkey_bytes = sock.recv(2048)
    server_pubkey = serialization.load_pem_public_key(server_pubkey_bytes)"""

    # loads in the trusted public key of VPN server
    with open("iron_server_public.pem", 'rb') as f:
        trusted_server_key = serialization.load_pem_public_key(f.read())

    # receiving of server key and then parsing of key
    server_public_key_bytes = sock.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Comparing fingerprints
    if public_key_fingerprint(trusted_server_key) != public_key_fingerprint(server_public_key):
        logging.error("[!] Server public key does not match trusted key! Possible MITM.")
        sock.close()
        exit(1)

    # server public key has been identified
    official_server_key = server_public_key
    logging.info("[+] Server public key verified successfully")

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
    logging.info("AES key exchanged")

    while True:
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
                    logging.warning("Replay attack detected: repeated nonce!")
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
                logging.error(f"Decryption error: {e}")

if __name__ == "__main__":
    vpn_client()
