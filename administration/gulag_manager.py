import os

from administration.vpn_logging.admin_logs.administration_log import AdminLog
from security.legionnaire.ips_manager import LegionnaireManager
from security.legionnaire.violation_management import ViolationManager
import socket
import threading
import vpn_logging
import stat

from security.session_tracking.sess_track import SessionTracker

admin_file = 'senate.sock'
admin_token = 'admin-token'
class AdminManager:
    # class is for managing clients that get sent to the gulag
    def __init__(self, admin_manager: LegionnaireManager):
        self.manager = admin_manager
        self.running = True

    def load_path(self):
        if os.path.exists(admin_file):
            os.remove(admin_file)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(admin_file)
        sock.listen(1)
        os.chmod(admin_file, stat.S_IRUSR | stat.S_IWUSR)
        # grants 0600 permissions
        AdminLog.log_server_activity("[AdminSocket] Listening on admin socket with 0600 permissions...")

        threading.Thread(target=self.accept_loop, args=(sock,), daemon=True).start()

    def accept_loop(self, sock):
        while self.running:
            conn, _ = sock.accept()
            threading.Thread(target=self.handle_connection, args=(conn,), daemon=True).start()

    def handle_connection(self, conn):
        try:
            data = conn.recv(1024).decode().strip()
            vpn_logging.info(f"[AdminSocket] Command received: {data}")

            parts = data.split()
            if not parts or parts[0] != admin_token:
                conn.sendall("Error: Unauthorized\n".encode())
                return

            cmd = " ".join(parts[1:])
            response = self.nkvd_headquarters(cmd)
            vpn_logging.info(f"[AdminSocket] Command '{cmd}' executed with result: {response}")
            conn.sendall(response.encode())
        except Exception as e:
            conn.sendall(f"Error: {str(e)}".encode())
        finally:
            conn.close()

    def compound_headquarters(self, cmd: str) -> str:
        parts = cmd.split()
        if not parts:
            return "No command given"

        action = parts[0].lower()

        if action == "list_clients":
            return self.list_clients()

        elif action == "disconnect" and len(parts) > 1:
            client_id = parts[1]
            if not client_id.isdigit():
                return "Invalid client_id"
            if self.manager.disconnect_client(client_id):
                return f"Client {client_id} disconnected"
            else:
                return f"Client {client_id} not found"

        elif action == "violations":
            return ViolationManager.dump_violations()

        elif action == "shutdown":
            self.running = False
            try:
                os.remove(admin_file)
            except Exception as e:
                vpn_logging.warning(f"Failed to remove admin socket file: {e}")
            return "Admin socket shutting down"

        return "Unknown command"
    def list_clients(self):
        # function returns a list of active client tuples
        active_clients = []
        for client, session_info in SessionTracker.client_sessions.items():
            active_clients.append((client, session_info))
        return active_clients