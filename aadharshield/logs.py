import logging
from logging.handlers import RotatingFileHandler

from . import config


def configure_logging():
    """Configure AadharShield logging with automatic file rotation."""

    config.LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("aadharshield")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Prevent duplicate file handlers.
    for existing_handler in logger.handlers[:]:
        if isinstance(existing_handler, RotatingFileHandler):
            logger.removeHandler(existing_handler)
            existing_handler.close()

    handler = RotatingFileHandler(
        filename=config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logger.info("AadharShield logging initialized")

    return logger


def get_logger(name=None):
    """Return an application logger."""
    if name:
        return logging.getLogger(f"aadharshield.{name}")

    return logging.getLogger("aadharshield")
