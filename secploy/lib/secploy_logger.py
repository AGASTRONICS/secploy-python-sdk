import logging
import sys

def setup_logger(log_level="INFO"):
    if log_level.upper() == "NONE":
        logging.disable(logging.CRITICAL)
        return

    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # ANSI escape codes
    COLORS = {
        "DEBUG": "\033[36m",   # Cyan
        "INFO": "\033[32m",    # Green
        "WARNING": "\033[33m", # Yellow
        "ERROR": "\033[31m",   # Red
        "CRITICAL": "\033[41m",# Red background
        "RESET": "\033[0m"     # Reset
    }

    class SecployFormatter(logging.Formatter):
        def format(self, record):
            log_fmt = f"[%(asctime)s] %(levelname)s: %(message)s"
            formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
            output = formatter.format(record)

            color = COLORS.get(record.levelname, COLORS["RESET"])
            return f"[SECPLOY] {color}{output}{COLORS['RESET']}"

    formatter = SecployFormatter()

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers (optional, prevents duplicate logs)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

secploy_logger = logging.getLogger(__name__)
