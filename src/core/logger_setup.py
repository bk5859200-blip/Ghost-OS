import logging
import os
from logging.handlers import RotatingFileHandler
from src.core.path_manager import PathManager


def setup_logger(log_dir=None, log_name="ghost_os.log", level=logging.INFO):
    """
    Structured logging: rotating file handler (5MB max with 3 backups)
    plus console output.
    """
    target_dir = log_dir or PathManager.get_logs_dir()
    os.makedirs(target_dir, exist_ok=True)
    log_path = os.path.join(target_dir, log_name)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root = logging.getLogger("ghost")
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(console_handler)
    root.propagate = False

    return root
