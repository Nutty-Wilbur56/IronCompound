import logging

"""Consider encrypting session logs"""
class AdminLog:
    admin_logger = 'iron_log.log'
    timeout_lock = logging.getLogger("iron_logger")
    admin_handler = logging.FileHandler(admin_logger)
    admin_handler.setFormatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    admin_logger.addHandler(admin_handler)
    admin_logger.setLevel(logging.INFO)

    @staticmethod
    def log_server_activity(activity):
        try:
            logging.info(activity)
        except Exception as e:
            pass