import logging
from logging.handlers import RotatingFileHandler

from . import config


def configure_logging(
    log_dir=None,
    file_name=None,
    max_bytes=None,
    backup_count=None,
):
    """Configure AadharShield logging with automatic file rotation."""

    from pathlib import Path

    log_dir = Path(log_dir or config.LOG_DIR)
    file_name = file_name or "aadharshield.log"
    max_bytes = max_bytes if max_bytes is not None else config.LOG_MAX_BYTES
    backup_count = backup_count if backup_count is not None else config.LOG_BACKUP_COUNT

    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / file_name

    logger = logging.getLogger("aadharshield")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Create the new handler before removing the existing one.
    new_handler = RotatingFileHandler(
        filename=log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    new_handler.setFormatter(formatter)

    # Replace existing rotating file handlers.
    for existing_handler in logger.handlers[:]:
        if isinstance(existing_handler, RotatingFileHandler):
            logger.removeHandler(existing_handler)
            existing_handler.close()

    logger.addHandler(new_handler)
    logger.info("AadharShield logging initialized")

    return logger


def get_logger(name=None):
    """Return an application logger."""
    if name:
        return logging.getLogger(f"aadharshield.{name}")

    return logging.getLogger("aadharshield")
