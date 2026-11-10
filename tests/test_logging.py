from aadharshield import config
from aadharshield.logs import configure_logging


def test_rotating_file_handler_creates_backups(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "LOG_DIR", tmp_path)
    monkeypatch.setattr(config, "LOG_FILE", tmp_path / "aadharshield.log")
    monkeypatch.setattr(config, "LOG_MAX_BYTES", 300)
    monkeypatch.setattr(config, "LOG_BACKUP_COUNT", 2)

    logger = configure_logging()

    try:
        for i in range(30):
            logger.info("Automated rotation test message number %s", i)

        for handler in logger.handlers:
            handler.flush()

        assert config.LOG_FILE.exists()
        assert (tmp_path / "aadharshield.log.1").exists()
        assert (tmp_path / "aadharshield.log.2").exists()

    finally:
        for handler in logger.handlers[:]:
            handler.flush()
            handler.close()
            logger.removeHandler(handler)
