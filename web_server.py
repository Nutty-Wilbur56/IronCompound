import socket

HOST, PORT = '0.0.0.0', 1648

open_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

open_socket.bind((HOST, PORT))
open_socket.listen(1)

print(f'listening on port {PORT}')

while True:
    client_connection, client_address = open_socket.accept()
    request = client_connection.recv(1024)
    print(request)
