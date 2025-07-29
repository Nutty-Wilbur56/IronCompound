import os
from security.legionnaire.ips_manager import LegionnaireManager
from security.legionnaire.violation_management import ViolationManager
import socket
import threading
import logging

NKDV_FILE = '../security/gulag/gulag.json'
class GulagManager:
    # class is for managing clients that get sent to the gulag
    def __init__(self, admin_manager: LegionnaireManager):
        self.manager = admin_manager
        self.running = True

    def load_path(self):
        if os.path.exists(NKDV_FILE):
            os.remove(NKDV_FILE)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(NKDV_FILE)
        sock.listen(1)
        logging.info("[AdminSocket] Listening on admin socket...")

        threading.Thread(target=self.accept_loop, args=(sock,), daemon=True).start()

    def accept_loop(self, sock):
        while self.running:
            conn, _ = sock.accept()
            threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()

    def handle_connection(self, conn):
        try:
            data = conn.recv(1024).decode().strip()
            logging.info(f"[AdminSocket] Command received: {data}")
            response = self.nkvd_headquarters(data)
            conn.sendall(response.encode())
        except Exception as e:
            conn.sendall(f"Error: {str(e)}".encode())
        finally:
            conn.close()

    def nkvd_headquarters(self, cmd: str) -> str:
        parts = cmd.split()
        if not parts:
            return "No command given"

        action = parts[0].lower()

        if action == "list_clients":
            return self._list_clients()

        elif action == "disconnect" and len(parts) > 1:
            client_id = parts[1]
            if self.manager.disconnect_client(client_id):
                return f"Client {client_id} disconnected"
            else:
                return f"Client {client_id} not found"

        elif action == "violations":
            return ViolationManager.dump_violations()

        elif action == "shutdown":
            self.running = False
            return "Admin socket shutting down"

        return "Unknown command"


    """def _list_clients(self):
        clients = self.manager.get_active_clients()
        if not clients:
            return "No active clients"
        return "\n".join([f"{cid} => {meta['ip']}:{meta['port']}" for cid, meta in clients.items()])"""