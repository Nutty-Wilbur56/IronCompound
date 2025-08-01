import logging

class LegionnaireLogger:
    legionnaire_logfile = 'security.log'
    timeout_lock = logging.getLogger("timeout_logger")

    # Properly initialize the main logger
    legionnaire_logger = logging.getLogger("legionnaire_logger")
    legionnaire_handler = logging.FileHandler(legionnaire_logfile)
    formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')
    legionnaire_handler.setFormatter(formatter)
    legionnaire_logger.addHandler(legionnaire_handler)
    legionnaire_logger.setLevel(logging.INFO)

    @staticmethod
    def log_legionnaire_activity(activity):
        try:
            logging.info(activity)
        except Exception as e:
            pass