import unittest
from wan_healthcheck.metrics import Metrics
from wan_healthcheck.state import HealthState


class MetricsTest(unittest.TestCase):
    def test_observe_state_and_transitions(self) -> None:
        metrics = Metrics()
        state = HealthState()
        state.probe_results = {"1.1.1.1": True, "8.8.8.8": False}
        metrics.observe_state(state, 100.0)
        get = metrics.registry.get_sample_value
        self.assertEqual(get("wan_healthcheck_healthy"), 1)
        self.assertEqual(get("wan_healthcheck_forced"), 0)
        self.assertEqual(
            get(
                "wan_healthcheck_probe_success",
                {"target": "1.1.1.1", "family": "ipv4"},
            ),
            1,
        )
        self.assertEqual(
            get(
                "wan_healthcheck_probe_success",
                {"target": "8.8.8.8", "family": "ipv4"},
            ),
            0,
        )
        self.assertEqual(get("wan_healthcheck_failovers_total"), 0)
        metrics.observe_effective_change(True)
        self.assertEqual(get("wan_healthcheck_failovers_total"), 1)
        self.assertEqual(get("wan_healthcheck_fallbacks_total"), 0)
        metrics.observe_effective_change(False)
        self.assertEqual(get("wan_healthcheck_fallbacks_total"), 1)
        self.assertIsNotNone(get("wan_healthcheck_last_state_change_timestamp_seconds"))

    def test_family_healthy_metric(self) -> None:
        metrics = Metrics()
        state = HealthState()
        # v4 still has a live target; v6 is entirely down.
        state.probe_results = {
            "1.1.1.1": True,
            "8.8.8.8": False,
            "2606:4700:4700::1111": False,
            "2001:4860:4860::8888": False,
        }
        metrics.observe_state(state, 100.0)
        get = metrics.registry.get_sample_value
        self.assertEqual(get("wan_healthcheck_family_healthy", {"family": "ipv4"}), 1)
        self.assertEqual(get("wan_healthcheck_family_healthy", {"family": "ipv6"}), 0)
        self.assertEqual(
            get("wan_healthcheck_family_failing_pct", {"family": "ipv4"}), 50
        )
        self.assertEqual(
            get("wan_healthcheck_family_failing_pct", {"family": "ipv6"}), 100
        )

    def test_family_healthy_follows_configured_pct(self) -> None:
        metrics = Metrics()
        state = HealthState()
        state.probe_results = {"1.1.1.1": True, "8.8.8.8": False}
        # Same 50%-failing input, opposite verdicts either side of the pct.
        metrics.observe_state(state, 100.0)
        get = metrics.registry.get_sample_value
        self.assertEqual(get("wan_healthcheck_family_healthy", {"family": "ipv4"}), 1)
        metrics.observe_state(state, 50.0)
        self.assertEqual(get("wan_healthcheck_family_healthy", {"family": "ipv4"}), 0)

    def test_threshold_metric_exported(self) -> None:
        metrics = Metrics()
        metrics.family_fail_pct_threshold.set(75.0)
        self.assertEqual(
            metrics.registry.get_sample_value(
                "wan_healthcheck_family_fail_pct_threshold"
            ),
            75.0,
        )
