import os
from ruamel.yaml import YAML


class ConfigError(Exception):
    pass


REQUIRED_SECTIONS = ["ghost", "monitoring", "thresholds", "notifications",
                      "watch_folders", "cleanup", "security", "automation", "safety"]


def load_config(config_path=None):
    """
    Loads and validates policy.yaml. Raises ConfigError on structural problems
    instead of silently substituting defaults for a broken config — Ghost OS
    would rather fail to start than run with a config nobody actually reviewed.
    """
    if config_path is None:
        from src.core.path_manager import PathManager
        config_path = PathManager.ensure_user_config()

    if not os.path.exists(config_path):
        raise ConfigError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        yaml_parser = YAML(typ='safe', pure=True)
        config = yaml_parser.load(f)

    if not isinstance(config, dict):
        raise ConfigError("Config file did not parse to a mapping — check YAML syntax.")

    missing = [s for s in REQUIRED_SECTIONS if s not in config]
    if missing:
        raise ConfigError(f"Config is missing required section(s): {missing}")

    _validate_numeric(config, ["monitoring", "system_interval_seconds"], min_value=0.5)
    _validate_numeric(config, ["monitoring", "process_interval_seconds"], min_value=1)
    _validate_numeric(config, ["thresholds", "cpu", "critical_percent"], min_value=1, max_value=100)
    _validate_numeric(config, ["thresholds", "memory", "critical_percent"], min_value=1, max_value=100)

    if not isinstance(config["watch_folders"], list) or not config["watch_folders"]:
        raise ConfigError("watch_folders must be a non-empty list.")

    if not isinstance(config["security"].get("protected_processes", []), list):
        raise ConfigError("security.protected_processes must be a list.")

    # Expand %USERPROFILE% / %TEMP% style env vars in path-bearing fields.
    config["watch_folders"] = [os.path.expandvars(p) for p in config["watch_folders"]]
    config["security"]["protected_paths"] = [
        os.path.expandvars(p) for p in config["security"].get("protected_paths", [])
    ]

    return config


def _validate_numeric(config, path, min_value=None, max_value=None):
    node = config
    for key in path[:-1]:
        node = node.get(key, {})
    value = node.get(path[-1])
    if value is None:
        raise ConfigError(f"Missing config value: {'.'.join(path)}")
    if not isinstance(value, (int, float)):
        raise ConfigError(f"Config value {'.'.join(path)} must be numeric, got {type(value)}")
    if min_value is not None and value < min_value:
        raise ConfigError(f"Config value {'.'.join(path)}={value} is below minimum {min_value}")
    if max_value is not None and value > max_value:
        raise ConfigError(f"Config value {'.'.join(path)}={value} exceeds maximum {max_value}")
