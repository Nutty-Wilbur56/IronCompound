import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def create_mock_ips():
    """
    Creates a mocked IPS manager instance for testing without loading
    real ML models or vpn_logging infrastructure.
    """
    from security.legionnaire.ips_manager import LegionnaireManager

    print("beginning of ips creation")

    # Patch ML Decision Engine
    with patch(
        "security.legionnaire.ips_manager.LegionnaireMLDecisionEngine",
        autospec=True
    ) as mock_engine_class:
        mock_engine_instance = MagicMock()
        mock_engine_instance.evaluate.return_value = {
            "risk_score": 0.5,
            "explanation": "Test explanation",
            "supervised_prob": 0.5,
            "unsupervised_mse": 0.01,
            "final_flag": False
        }
        mock_engine_class.return_value = mock_engine_instance

        with patch(
            "administration.vpn_policy.iron_policy.IronPolicy"
        ) as rule_engine_class:
            rule_engine_instance = MagicMock()

        # Patch Logger
        with patch(
            "administration.vpn_logging.security_logs.legionnaire_logger.LegionnaireLogger",
            autospec=True
        ) as mock_logger_class:
            mock_logger_instance = MagicMock()
            mock_logger_class.return_value = mock_logger_instance

            # Create the IPS Manager
            ips = LegionnaireManager()
            ips.ml_engine = mock_engine_instance
            ips.policy_engine = MagicMock()
            ips.policy_engine.active_compound_rules = []

    print("end of ips creation")
    return ips


def test_mock_ips_creation(create_mock_ips):
    """
    Basic smoke test to ensure our mocked IPS Manager is created.
    """
    ips = create_mock_ips
    assert ips is not None
    assert hasattr(ips, "ml_engine")
    assert hasattr(ips, "policy_engine")
    # Validate ML engine mock
    result = ips.ml_engine.evaluate("fake_session")
    assert result["risk_score"] == 0.5
    assert result["final_flag"] is False
