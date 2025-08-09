import time
from collections import deque, defaultdict


class AdaptableRiskMonitor:
    # class for managing risk with potential adversarial sessions
    session_window_size = 50
    risk_scores = deque(maxlen=session_window_size)
    risk_average = 0

    @classmethod
    def update(cls, risk_score):
        cls.risk_scores.append(risk_score)
        AdaptableRiskMonitor.risk_average()

    @classmethod
    def risk_average(cls):
        AdaptableRiskMonitor.risk_average = sum(cls.risk_scores) / len(cls.risk_scores) if cls.risk_scores else 0.0
        return sum(cls.risk_scores) / len(cls.risk_scores) if cls.risk_scores else 0.0

class AdaptiveThresholdManager:
    # class is for enabling adaptive threshold managers

    # global scope thresholds
    ml_high_threshold = 0.75
    ml_critical_threshold = 0.85

    # global scope stats for adaptation
    benign_anomaly_count = 0
    false_positive_feedback = 0
    adaptation_interval = 50 #variable recalculates every 50 sessions
    session_count = 0

    """
    Beginning of new code
    """
    # client adaptive threshold tracking
    risk_score_history = defaultdict(list)
    false_positive_reports = defaultdict(int)
    last_adjustment = defaultdict(float)

    # client stats for adaptation
    min_risk_threshold = 0.6
    max_risk_threshold = 0.9
    adjust_interval = 300  # seconds

    @classmethod
    def record_risk_score(cls, client_id, score):
        cls.risk_score_history[client_id].append(score)
        if len(cls.risk_score_history[client_id]) > 100:
            cls.risk_score_history[client_id].pop(0)

    @classmethod
    def feedback_false_positive(cls, client_id):
        cls.false_positive_reports[client_id] += 1

    @classmethod
    def get_adaptive_threshold(cls, client_id):
        now = time.time()
        if now - cls.last_adjustment[client_id] < cls.adjust_interval:
            return cls.min_risk_threshold

        scores = cls.risk_score_history[client_id]
        if not scores:
            return cls.min_risk_threshold

        avg_score = sum(scores) / len(scores)
        false_positives = cls.false_positive_reports[client_id]

        # Example: lower threshold slightly if lots of FPs or avg score is low
        if false_positives >= 3 or avg_score < 0.4:
            threshold = max(cls.min_risk_threshold, avg_score - 0.1)
        else:
            threshold = min(cls.max_risk_threshold, avg_score + 0.1)

        cls.last_adjustment[client_id] = now
        return round(threshold, 2)

    @classmethod
    def risk_average(cls):
        all_scores = [score for scores in cls.risk_score_history.values() for score in scores]
        if not all_scores:
            return 0.0
        return sum(all_scores) / len(all_scores)
    """Ending of new code"""
    @classmethod
    def false_positive_outcome(cls):
        cls.false_positive_feedback += 1
        cls.false_positive_feedback += 1

    @classmethod
    def register_benign_anomaly(cls):
        # function registers an anomaly detected in a session, however anomaly is benign
        cls.benign_anomaly_count += 1

    @classmethod
    def register_session(cls):
        # function will be called from within session tracking when session is created
        cls.session_count += 1
        if cls.session_count % cls.adaptation_interval == 0:
            cls.recalculate_thresholds()

    @classmethod
    def recalculate_thresholds(cls):
        average_risk = AdaptableRiskMonitor.risk_average()
        # Adjust critical threshold slightly if overall risk is very low or high
        if average_risk < 0.4:
            cls.ml_critical_threshold = max(0.8, cls.ml_critical_threshold - 0.02)
        elif average_risk > 0.6:
            cls.ml_critical_threshold = min(0.9, cls.ml_critical_threshold + 0.02)

        # Adjust high threshold based on false positives
        if cls.false_positive_feedback > 5:
            cls.ml_high_threshold = min(0.8, cls.ml_high_threshold + 0.02)
            cls.false_positive_feedback = 0

        # Reset benign anomaly counter
        cls.benign_anomaly_counter = 0