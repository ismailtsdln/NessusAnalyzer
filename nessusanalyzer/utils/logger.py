import logging
import sys
from rich.logging import RichHandler

def setup_logger(name: str = "nessusanalyzer", level: int = logging.INFO):
    """Sets up a rich logger for the application."""
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    return logging.getLogger(name)

logger = setup_logger()
