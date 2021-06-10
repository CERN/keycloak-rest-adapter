import logging
import sys
import datetime
import json
from logging.handlers import TimedRotatingFileHandler


class JsonFormatter(logging.Formatter):
    def formatException(self, exc_info):
        result = super(JsonFormatter, self).formatException(exc_info)
        # We want the exception in JSON format for Monit.
        json_result = {
            "timestamp": f"{datetime.now()}",
            "level": "ERROR",
            "logger": "app",
            "message": f"{result}",
        }
        return json.dumps(json_result)

    def format(self, record):
        return super(JsonFormatter, self).format(record)


def configure_logging(log_dir):
    """Logging setup
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # adds console handler to logger instance the first time this code is called
    # avoids adding extra handlers to the instance, which causes duplicate logs msgs
    if not len(logger.handlers):
        logger.addHandler(console_handler())
        logger.addHandler(json_handler(log_dir))

    # Requests logs some stuff at INFO that we don't want
    # unless we have DEBUG
    requests_log = logging.getLogger("requests")
    requests_log.setLevel(logging.ERROR)
    return logger


def console_handler():
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
    )
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    return console


def json_handler(log_dir):
    # These logs are sent to Monit (and stored for 12 hours on the machine).
    json_handler = TimedRotatingFileHandler(
        filename=f"{log_dir}/keycloak-rest-adapter.log",
        interval=12,
        when="H",
        backupCount=1,
    )
    json_formatter = JsonFormatter(
        '{"timestamp":"%(created)s", "level":"%(levelname)s", "logger":"%(module)s", "message":"%(message)s"}'
    )
    json_handler.setFormatter(json_formatter)
    return json_handler
