import logging

# Creation of violation manager logger
violation_logger = logging.getLogger("ips")
violation_logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("logs/violations.log")
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
# ending

class ViolationManager:

    @ staticmethod
    def record_violation(session, rule_name, client_id):
        session.set_default("violations", {})
        session['violations'].setdefault(rule_name, 0)
        session['violations'][rule_name] += 1

        violation_logger.warning(f"[Client {client_id}] Rule violated: {rule_name} (#{session['violations'][rule_name]})")

        if session["violations"][rule_name] == "Flooding Violation":
            total = (session["violations"]['Flooding Violation'])
            if total > 1:
                session["flagged_for_disconnect"] = True
                violation_logger.warning(f"[Client {client_id}] Exceeded violation threshold — plan for disconnect")

        elif session["violations"][rule_name] == "Throttling Violation":
            total = (session["violations"]['Throttling Violation'])
            if total > 3:
                session["flagged_for_disconnect"] = True
                violation_logger.warning(f"[Client {client_id}] Exceeded violation threshold — plan for disconnect")

        elif session["violations"][rule_name] == "Replay Violation":
            total = (session["violations"]['Replay Violation'])
            if total > 2:
                session["flagged_for_disconnect"] = True
                violation_logger.warning(f"[Client {client_id}] Exceeded violation threshold — plan for disconnect")