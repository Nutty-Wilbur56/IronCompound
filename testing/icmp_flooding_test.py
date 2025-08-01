import time
import unittest
from collections import defaultdict
from security.legionnaire.flooding.flooding_rule_manager import  IcmpFloodingRuleManager
from

from security.session_tracking.sess_track import SessionTracker


class TestIcmpFloodingRuleManager(unittest.TestCase):
    def setUp(self):
        self.client_id = "test-client"
        # Reset attempts and flags before each test
        IcmpFloodingRuleManager.icmp_attempts = defaultdict(list)
        IcmpFloodingRuleManager.last_flagged = defaultdict(float)

    def test_icmp_flooding_triggered(self):
        now = time.time()
        # Simulate ICMP echo requests: 100 packets in the last 10 seconds
        IcmpFloodingRuleManager.icmp_attempts[self.client_id] = [now - 1] * 100

        # Create a mock session object with client_id
        mock_session = SessionTracker.client_sessions[clie_]

        # Run detection
        result = IcmpFloodingRuleManager.should_session_be_flagged(mock_session)

        self.assertTrue(result, "ICMP flood should be detected and flagged.")

    def test_icmp_below_threshold(self):
        now = time.time()
        # Simulate only 30 packets
        IcmpFloodingRuleManager.icmp_attempts[self.client_id] = [now - 1] * 30

        mock_session =
        result = IcmpFloodingRuleManager.should_session_be_flagged(mock_session)

        self.assertFalse(result, "Should not flag below-threshold ICMP echo requests.")

    def test_icmp_flooding_within_cooldown(self):
        now = time.time()
        IcmpFloodingRuleManager.icmp_attempts[self.client_id] = [now - 1] * 100
        IcmpFloodingRuleManager.last_flagged[self.client_id] = now - 5  # less than COOLDOWN

        mock_session = Session(client_id=self.client_id)
        result = IcmpFloodingRuleManager.should_session_be_flagged(mock_session)

        self.assertFalse(result, "Should not re-flag client within cooldown period.")


if __name__ == '__main__':
    unittest.main()
