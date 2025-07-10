def vpn_server(host='0.0.0.0', port=1871):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    tun = create_tun('tun0')
    set_up_tun('tun0', '10.8.0.1')

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[+] VPN server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[+] Client connected from {addr}")

        client_pubkey_bytes = client_socket.recv(2048)
        try:
            client_pubkey = load_pem_public_key_from_bytes(client_pubkey_bytes)
        except Exception as e:
            print("[-] Invalid public key received from client:", e)
            client_socket.close()
            continue

        if not is_client_authorized(client_pubkey):
            print("[-] Unauthorized client. Connection closed.")
            client_socket.close()
            continue

        print("[+] Client is authorized")
        client_socket.sendall(public_key_bytes)

        enc_key = client_socket.recv(4096)
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aes = AESGCM(aes_key)
        print("[+] AES key exchange complete")

        while True:
            r, _, _ = select.select([client_socket, tun], [], [])
            if client_socket in r:
                data = client_socket.recv(4096)
                if not data:
                    break
                nonce = data[:12]
                ciphertext = data[12:]
                try:
                    packet = aes.decrypt(nonce, ciphertext, None)
                    os.write(tun, packet)
                except Exception as e:
                    print("[-] Decryption error:", e)

            if tun in r:
                packet = os.read(tun, 2048)
                nonce = os.urandom(12)
                encrypted_packet = nonce + aes.encrypt(nonce, packet, None)
                client_socket.sendall(encrypted_packet)
