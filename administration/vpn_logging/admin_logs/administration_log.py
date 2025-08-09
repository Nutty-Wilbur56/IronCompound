import logging

"""Consider encrypting session logs"""
class AdminLog:
    LOG_FILE = 'administration_log.log'

    # Set up logger
    timeout_lock = logging.getLogger("admin_logger")
    timeout_lock.setLevel(logging.INFO)

    file_handler = logging.FileHandler(LOG_FILE)
    formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)

    # Avoid adding multiple handlers if the logger is already configured
    if not timeout_lock.handlers:
        timeout_lock.addHandler(file_handler)

    @staticmethod
    def log_server_activity(activity):
        try:
            AdminLog.timeout_lock.info(str(activity))
        except Exception as e:
            # Optionally, log this to stderr or another fallback
            pass