import logging
import unittest
from wan_healthcheck.log import GlogFormatter


class GlogFormatterTest(unittest.TestCase):
    def _format(self, level: int) -> str:
        record = logging.LogRecord(
            name="wan_healthcheck",
            level=level,
            pathname="wan_healthcheck.py",
            lineno=123,
            msg="hello %s",
            args=("world",),
            exc_info=None,
        )
        return GlogFormatter().format(record)

    def test_info_shape(self) -> None:
        line = self._format(logging.INFO)
        self.assertRegex(
            line,
            r"^I\d{4} \d{2}:\d{2}:\d{2}\.\d{6} \d+ wan_healthcheck\.py:123\] "
            r"hello world$",
        )

    def test_level_letters(self) -> None:
        self.assertTrue(self._format(logging.WARNING).startswith("W"))
        self.assertTrue(self._format(logging.ERROR).startswith("E"))
        self.assertTrue(self._format(logging.CRITICAL).startswith("F"))
        self.assertTrue(self._format(logging.DEBUG).startswith("I"))
