"""
Ghost OS entrypoint.

Startup sequence (spec section 34):
  single-instance check -> load & validate config -> set up logging ->
  GhostCore.start() (spawns background watchers) -> tray icon (blocks).
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.core.single_instance import SingleInstance
from src.core.config_loader import load_config, ConfigError
from src.core.logger_setup import setup_logger
from src.core.ghost_core import GhostCore
from src.tray.tray_app import TrayApp


def _global_exception_handler(exc_type, exc_value, exc_traceback):
    """Logs any uncaught exception with full traceback before terminating."""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger = setup_logger()
    logger.critical("Uncaught top-level exception crashed Ghost OS:", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = _global_exception_handler


def main():
    instance_guard = SingleInstance()
    if not instance_guard.acquire():
        print("Ghost OS is already running.")
        sys.exit(0)

    logger = setup_logger()
    logger.info("Ghost OS starting up.")

    try:
        config_arg = sys.argv[1] if (len(sys.argv) > 1 and not sys.argv[1].startswith("-")) else None
        try:
            config = load_config(config_arg)
        except ConfigError as e:
            logger.error(f"Refusing to start with invalid config: {e}")
            sys.exit(1)

        if config["safety"]["dry_run"]:
            logger.warning("DRY RUN mode is ON — detections will be logged/notified but no files will be "
                            "deleted or quarantined. Set safety.dry_run: false in config/policy.yaml when ready.")

        core = GhostCore(config)
        core.start()

        tray = TrayApp(core)
        try:
            tray.run()  # blocks until Exit is chosen
        finally:
            core.stop()
            instance_guard.release()
            logger.info("Ghost OS shut down.")
    except Exception as e:
        logger.critical(f"Fatal error in Ghost OS main runtime loop: {e}", exc_info=True)
        instance_guard.release()
        sys.exit(1)


if __name__ == "__main__":
    main()
