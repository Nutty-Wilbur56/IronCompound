import logging

class LegionnaireLogger:
    legionnaire_logger = 'security.log'
    timeout_lock = logging.getLogger("timeout_logger")
    legionnaire_handler = logging.FileHandler(legionnaire_logger)
    legionnaire_handler.setFormatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    legionnaire_logger.addHandler(legionnaire_handler)
    legionnaire_logger.setLevel(logging.INFO)

    @staticmethod
    def log_legionnaire_activity(activity):
        try:
            logging.info(activity)
        except Exception as e:
            pass