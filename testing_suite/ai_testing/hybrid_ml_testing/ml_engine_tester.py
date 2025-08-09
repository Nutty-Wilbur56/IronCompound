import numpy as np
import torch
import torch.nn.functional as F

from artificial_intelligence.initial_training.session_classifier import LegionnaireMLDecisionEngine


def hybrid_ml_tester(session_info):
    ml_instance = LegionnaireMLDecisionEngine()

    return ml_instance.evaluate(session_info)
try:
    """Test One"""
    session_info1 = {
        "bytes_sent": 75456,
        "bytes_received": 7564,
        "replay_violations": 1,
        "throttle_violations": 0,
        "syn_flood_violations": 1,
        "icmp_flood_violations": 1,
        "duration": 23412
    }


    test1 = hybrid_ml_tester(session_info1)

    assert test1['final_flag'] == True
    """Ending of Test one"""

    """Beginning of Test Two"""
    session_info2 = {
        "bytes_sent": 8000,
        "bytes_received": 450,
        "replay_violations": 0,
        "throttle_violations": 0,
        "syn_flood_violations": 0,
        "icmp_flood_violations": 0,
        "duration": 6000
    }

    test2 = hybrid_ml_tester(session_info2)
    assert test2['final_flag'] == False

    """Ending of Test two"""

    """Beginning of Test Three"""
    session_info3 = {
        "bytes_sent": 586747,
        "bytes_received": 45000,
        "replay_violations": 0,
        "throttle_violations": 0,
        "syn_flood_violations": 0,
        "icmp_flood_violations": 0,
        "duration": 3434830
    }

    test3 = hybrid_ml_tester(session_info3)
    assert test3['final_flag'] == True

    """Ending of Test three"""

    """Beginning of Test four"""
    session_info4 = {
        "bytes_sent": 8747576,
        "bytes_received": 45000,
        "replay_violations": 1,
        "throttle_violations": 3,
        "syn_flood_violations": 0,
        "icmp_flood_violations": 0,
        "duration": 3434830
    }

    test4 = hybrid_ml_tester(session_info4)
    assert test4['explanation']['supervised_model_triggered'] == True
    """Ending of Test four"""

    """Beginning of Test five"""
    session_info5 = {
        "bytes_sent": 8747576,
        "bytes_received": 45000,
        "replay_violations": 1,
        "throttle_violations": 3,
        "syn_flood_violations": 0,
        "icmp_flood_violations": 0,
        "duration": 3434830
    }

    test5 = hybrid_ml_tester(session_info5)
    assert test5['explanation']['autoencoder_unsupervised_model_triggered'] == True
    """Ending of Test five"""

    """Beginning of Test six"""
    session_info6 = {
        "bytes_sent": 874757,
        "bytes_received": 78594,
        "replay_violations": 0,
        "throttle_violations": 3,
        "syn_flood_violations": 3,
        "icmp_flood_violations": 0,
        "duration": 7880
    }

    test6 = hybrid_ml_tester(session_info6)
    assert test6['explanation']['autoencoder_unsupervised_model_triggered'] == True
    """Ending of Test six"""
except Exception as e:
    print(f"Assertion failure {e}")
