import json
from ..core.models import NessusReport
from ..utils.logger import logger

class JSONFormatter:
    def __init__(self, report: NessusReport):
        self.report = report

    def export(self, output_path: str):
        """Exports the report to a JSON file."""
        logger.info(f"Exporting report to JSON: {output_path}")
        try:
            with open(output_path, mode='w', encoding='utf-8') as f:
                json.dump(self.report.model_dump(), f, indent=4)
            logger.info("JSON export completed successfully.")
        except Exception as e:
            logger.error(f"Error during JSON export: {e}")
            raise
