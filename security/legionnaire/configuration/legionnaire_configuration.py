import json
import os
from threading import Lock

from administration.vpn_logging.security_logs.legionnaire_logger import LegionnaireLogger


class LegionnaireConfiguration:
    """
    class handles global configuration of Legionnaire behavior
    Currently supports toggling monitor-only mode. in this mode
    application of the automated and hybrid rule engines are suppressed
    """
    configuration_file = 'configuration.json'
    config_lock = Lock()
    is_in_monitor_mode = False
    # variable for tracking whether IPS is in passive monitoring mode or not
    @classmethod
    def load(cls):
        # load the config file from hard drive or disk if available
        with cls.config_lock:
            if os.path.exists(cls.configuration_file):
                try:
                    with open(cls.configuration_file, 'r') as config_file:
                        config_data = json.load(config_file)
                        cls.is_in_monitor_mode = config_data.get('monitor_only_mode', False)

                except Exception as e:
                    LegionnaireLogger.log_legionnaire_activity(f"[Legionnaire] Failed to load config: {e}")

    @classmethod
    def save(cls):
        """Save current IPS config to disk."""
        with cls.config_lock:
            try:
                with open(cls.configuration_file, "w") as f:
                    json.dump({
                        "monitor_only_mode": cls.is_in_monitor_mode
                    }, f, indent=4)
            except Exception as e:
                print(f"[IPSConfig] Failed to save config: {e}")

    @classmethod
    def set_monitor_only(cls, state: bool):
        """Enable or disable monitor-only mode."""
        with cls.config_lock:
            cls.monitor_only_mode = state
            cls.save()
            LegionnaireLogger.log_legionnaire_activity(
                f"[IPS-CONFIG] Monitor-only mode set to: {state}"
            )

    @classmethod
    def toggle_monitor_only(cls):
        """Toggle monitor-only mode."""
        with cls.config_lock:
            cls.monitor_only_mode = not cls.monitor_only_mode
            cls.save()
            LegionnaireLogger.log_legionnaire_activity(
                f"[IPS-CONFIG] Monitor-only mode toggled to: {cls.monitor_only_mode}"
            )

    @classmethod
    def is_monitor_mode(cls):

        return cls.monitor_only_mode
