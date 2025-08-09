import logging
"""Consider encrypting security logs"""
class LegionnaireLogger:
    legionnaire_logfile = 'security.log'
    timeout_lock = logging.getLogger("security_logger")

    # Properly initialize the main logger
    file_handler = logging.FileHandler(legionnaire_logfile)
    formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)

    # Avoid adding multiple handlers if the logger is already configured
    if not timeout_lock.handlers:
        timeout_lock.addHandler(file_handler)

    @staticmethod
    def log_legionnaire_activity(activity):
        try:
            LegionnaireLogger.timeout_lock.info(activity)
        except Exception as e:
            pass