LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "root": {
        "handlers": ["default"],
        "level": "INFO",
    },
    "loggers": {
        "httpx": {
            "level": "WARNING",
        },
        "sqlalchemy.engine": {
            "level": "WARNING",
        },
        "uvicorn.access": {
            "level": "WARNING",
        },
    },
}
