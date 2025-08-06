import logging

"""Consider encrypting session logs"""
class IronLog:
    iron_logger = 'iron_log.log'
    timeout_lock = logging.getLogger("iron_logger")
    iron_handler = logging.FileHandler(iron_logger)
    iron_handler.setFormatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    iron_logger.addHandler(iron_handler)
    iron_logger.setLevel(logging.INFO)

    @staticmethod
    def log_server_activity(activity):
        try:
            logging.info(activity)
        except Exception as e:
            pass