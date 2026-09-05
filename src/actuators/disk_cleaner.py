from src.actions.cleaner import SystemCleaner
from src.decision.safety_engine import SafetyEngine


class DiskCleaner:
    """
    Actuator wrapper providing safe disk cleanup that routes strictly through SafetyEngine.
    """

    def __init__(self, config=None, db_mgr=None):
        safety = SafetyEngine(config or {"safety": {"dry_run": True}})
        self.cleaner = SystemCleaner(safety, db_mgr=db_mgr)

    def preview(self):
        return self.cleaner.preview()

    def clean_temp_directories(self):
        preview = self.cleaner.preview()
        return self.cleaner.execute(preview["candidates"])
