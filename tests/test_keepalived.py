import os
import tempfile
import time
import unittest
from pathlib import Path
from wan_healthcheck.keepalived import state_since, write_track_file


class TrackFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "att_weight"

    def test_write_and_idempotency(self) -> None:
        self.assertTrue(write_track_file(self.path, 1))
        self.assertEqual(self.path.read_text(), "1\n")
        self.assertFalse(write_track_file(self.path, 1))
        self.assertTrue(write_track_file(self.path, 0))
        self.assertEqual(self.path.read_text(), "0\n")

    def test_tmpfiles_seed_without_newline_is_not_rewritten(self) -> None:
        # systemd-tmpfiles seeds the file as a bare "0" (1 byte, no newline).
        self.path.write_text("0")
        self.assertFalse(write_track_file(self.path, 0))
        self.assertEqual(self.path.read_text(), "0", "must not rewrite")
        self.assertTrue(write_track_file(self.path, 1))

    def test_atomic_no_tmp_leftover(self) -> None:
        write_track_file(self.path, 1)
        leftovers = [p.name for p in self.path.parent.iterdir()]
        self.assertEqual(leftovers, ["att_weight"])


class StateSinceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "att_weight"

    def test_uses_mtime(self) -> None:
        write_track_file(self.path, 0)
        os.utime(self.path, (1_000_000, 1_000_000))
        self.assertEqual(state_since(self.path, fallback=42.0), 1_000_000)

    def test_missing_file_falls_back(self) -> None:
        self.assertEqual(state_since(self.path, fallback=42.0), 42.0)

    def test_mtime_only_moves_on_real_change(self) -> None:
        write_track_file(self.path, 0)
        os.utime(self.path, (1_000_000, 1_000_000))
        # Re-writing the same value must not touch the file...
        self.assertFalse(write_track_file(self.path, 0))
        self.assertEqual(state_since(self.path, fallback=0.0), 1_000_000)
        # ...but a real transition must.
        self.assertTrue(write_track_file(self.path, 1))
        self.assertGreater(state_since(self.path, fallback=0.0), 1_000_000)

    def test_never_zero_for_dashboard(self) -> None:
        # The 1970 bug: a 0 here renders as ~57 years on a duration panel.
        self.assertNotEqual(state_since(self.path, fallback=time.time()), 0)
