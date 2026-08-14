"""glog-style logging, so output matches the rest of the fleet."""

import logging
import sys
from datetime import datetime
from typing import Final

from mypy_extensions import mypyc_attr

LOG: Final[logging.Logger] = logging.getLogger("wan_healthcheck")


@mypyc_attr(native_class=False)
class GlogFormatter(logging.Formatter):
    """Google glog-style log lines: I0812 14:23:45.123456 pid file.py:123] msg"""

    _LEVELS: Final[dict[str, str]] = {
        "DEBUG": "I",
        "INFO": "I",
        "WARNING": "W",
        "ERROR": "E",
        "CRITICAL": "F",
    }

    def format(self, record: logging.LogRecord) -> str:
        level = self._LEVELS.get(record.levelname, "I")
        when = datetime.fromtimestamp(record.created)
        micros = int((record.created % 1) * 1_000_000)
        return (
            f"{level}{when:%m%d %H:%M:%S}.{micros:06d} {record.process} "
            f"{record.filename}:{record.lineno}] {record.getMessage()}"
        )


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(GlogFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
