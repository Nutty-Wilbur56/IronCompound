import time
import logging
import os

logger = logging.getLogger('activity')

def check_user_activity(session, client_id, inactivity_check, aes, client_socket):
    # checking user activity to ensure that user is not an adversary wasting network resources
    current_time = time.time()
    # capturing current time of check
    last_active = session.get('last_activity', current_time)

    if current_time - last_active > inactivity_check:
        warned = session.get("client warned", False)

        if not warned:
            """Process of warning user"""
            # beginning of warning
            try:
                # sending a warning packet to client stating that they have been inactive for too long
                warning = (b"ATTENTION!!! you have been inactive for" + f"{inactivity_check // 60} minutes.".encode() + b"Please "
                                       b"ensure that you become active once again in the next five minutes, "
                                       b"otherwise you'll be removed from the server due to inactivity.")
                nonce = os.random(12)
                encrypt = nonce + aes.encrypt(nonce, warning, None)
                client_socket.sendall(encrypt)
                session['client warned'] = True
                return "warned"
            # ending of warning

            except Exception as e:
                logger.warning(f'[Client {client_id}] failed to send warning: {e}')
        else:
            return "kicked"

    return "ok"
