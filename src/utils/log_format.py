import logging
import sys


def configure_logging(role: str, log_format: str = "full") -> None:
    if log_format == "compact":
        fmt = "%(levelname)s\t%(message)s"
    else:
        fmt = f"%(asctime)s\t%(process)d({role})\t%(levelname)s\t%(message)s"
    logging.basicConfig(level=logging.INFO, force=True, format=fmt, handlers=[logging.StreamHandler(sys.stderr)])
