import unittest
from wan_healthcheck.state import HealthState


class HealthStateTest(unittest.TestCase):
    def test_fall_hysteresis(self) -> None:
        state = HealthState()
        self.assertFalse(state.record_round(False, fall=3, rise=2))
        self.assertFalse(state.record_round(False, fall=3, rise=2))
        self.assertTrue(state.healthy)
        self.assertTrue(state.record_round(False, fall=3, rise=2))
        self.assertFalse(state.healthy)
        self.assertTrue(state.failed_over)

    def test_interleaved_success_resets_fall(self) -> None:
        state = HealthState()
        state.record_round(False, fall=2, rise=2)
        state.record_round(True, fall=2, rise=2)
        self.assertFalse(state.record_round(False, fall=2, rise=2))
        self.assertTrue(state.healthy)

    def test_rise_hysteresis(self) -> None:
        state = HealthState(healthy=False)
        self.assertFalse(state.record_round(True, fall=2, rise=3))
        state.record_round(False, fall=2, rise=3)  # resets the rise streak
        self.assertFalse(state.record_round(True, fall=2, rise=3))
        self.assertFalse(state.record_round(True, fall=2, rise=3))
        self.assertTrue(state.record_round(True, fall=2, rise=3))
        self.assertTrue(state.healthy)

    def test_forced_overrides_healthy_verdict(self) -> None:
        state = HealthState()
        self.assertFalse(state.failed_over)
        state.forced_failover = True
        self.assertTrue(state.failed_over)
        self.assertTrue(state.healthy)

    def test_snapshot_keys(self) -> None:
        snapshot = HealthState().snapshot(100.0)
        for key in (
            "healthy",
            "forced_failover",
            "failed_over",
            "consecutive_successes",
            "consecutive_failures",
            "last_change",
            "last_change_iso",
            "probe_results",
        ):
            self.assertIn(key, snapshot)
