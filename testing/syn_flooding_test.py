from security.legionnaire.flooding.flooding_rule_manager import SynFloodingRuleManager
import time

def test_syn_flood_detection():
    client_id = "test-client"
    now = time.time()
    # Simulate burst of SYNs
    SynFloodingRuleManager.syn_attempts[client_id] = [now - 1] * 150

    assert SynFloodingRuleManager.should_session_be_flagged(client_id) is True

test_syn_flood_detection()