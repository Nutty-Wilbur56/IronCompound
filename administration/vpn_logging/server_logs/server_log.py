import logging

"""Consider encrypting session logs"""
class IronLog:
    iron_log_file = 'iron_log.log'

    timeout_lock = logging.getLogger("iron_logger")

    file_handler = logging.FileHandler(iron_log_file)
    formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)

    # Avoid adding multiple handlers if the logger is already configured
    if not timeout_lock.handlers:
        timeout_lock.addHandler(file_handler)

    @staticmethod
    def log_server_activity(activity):
        try:
            IronLog.timeout_lock.info(activity)
        except Exception as e:
            pass