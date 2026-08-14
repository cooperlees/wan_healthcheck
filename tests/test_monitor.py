import asyncio
import unittest
from typing import Any
from unittest import mock
from wan_healthcheck import monitor as monitor_mod
from wan_healthcheck.metrics import Metrics
from wan_healthcheck.monitor import Monitor
from wan_healthcheck.state import HealthState
from .helpers import make_settings


class PeerGateTest(unittest.IsolatedAsyncioTestCase):
    """Failing over to a backup that has no internet makes an outage worse."""

    def _monitor(self, **overrides: Any) -> Monitor:
        settings = make_settings(fall=2, rise=2, **overrides)
        actions = mock.MagicMock()
        actions.ensure_failover = mock.AsyncMock()
        actions.ensure_fallback = mock.AsyncMock()
        return Monitor(settings, HealthState(), Metrics(), actions)

    @staticmethod
    def _results(ok: bool) -> dict[str, bool]:
        return {t: ok for t in ("1.1.1.1", "8.8.8.8", "2606::1", "2001::8")}

    def test_no_peer_configured_is_transparent(self) -> None:
        state = HealthState(healthy=False)
        self.assertTrue(state.failed_over)
        self.assertFalse(state.failover_suppressed)

    def test_unhealthy_peer_blocks_failover(self) -> None:
        state = HealthState(healthy=False, peer_healthy=False)
        self.assertFalse(state.failed_over)
        self.assertTrue(state.failover_suppressed)

    def test_forced_bypasses_the_gate(self) -> None:
        state = HealthState(healthy=False, peer_healthy=False, forced_failover=True)
        self.assertTrue(state.failed_over)

    def test_healthy_peer_allows_failover(self) -> None:
        state = HealthState(healthy=False, peer_healthy=True)
        self.assertTrue(state.failed_over)

    async def test_degraded_wan_with_dead_peer_holds_position(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            monitor_mod,
            "api_request",
            new=mock.AsyncMock(return_value={"healthy": False}),
        ):
            await monitor.tick(self._results(False))
            await monitor.tick(self._results(False))
        self.assertFalse(monitor.state.healthy)
        self.assertTrue(monitor.state.failover_suppressed)
        monitor.actions.ensure_failover.assert_not_awaited()
        get = monitor.metrics.registry.get_sample_value
        self.assertEqual(get("wan_healthcheck_failover_suppressed"), 1)
        self.assertEqual(get("wan_healthcheck_failed_over"), 0)

    async def test_degraded_wan_with_live_peer_fails_over(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            monitor_mod,
            "api_request",
            new=mock.AsyncMock(return_value={"healthy": True}),
        ):
            await monitor.tick(self._results(False))
            await monitor.tick(self._results(False))
        monitor.actions.ensure_failover.assert_awaited()
        self.assertEqual(
            monitor.metrics.registry.get_sample_value("wan_healthcheck_failed_over"),
            1,
        )

    async def test_peer_unreachable_tolerated_then_marked_down(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            monitor_mod, "api_request", new=mock.AsyncMock(return_value=None)
        ):
            await monitor.tick(self._results(True))
            # One blip must not disqualify the peer (fall=2 here).
            self.assertTrue(monitor.state.peer_healthy)
            self.assertFalse(monitor.state.peer_reachable)
            await monitor.tick(self._results(True))
        self.assertFalse(monitor.state.peer_healthy)
        self.assertEqual(
            monitor.metrics.registry.get_sample_value("wan_healthcheck_peer_reachable"),
            0,
        )

    async def test_peer_that_has_itself_failed_over_is_still_viable(self) -> None:
        # A peer reporting failed_over moved traffic somewhere; that does not
        # mean it lacks internet.
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            monitor_mod,
            "api_request",
            new=mock.AsyncMock(return_value={"healthy": True, "failed_over": True}),
        ):
            await monitor.tick(self._results(False))
            await monitor.tick(self._results(False))
        monitor.actions.ensure_failover.assert_awaited()

    async def test_peer_polled_at_its_own_url(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        api = mock.AsyncMock(return_value={"healthy": True})
        with mock.patch.object(monitor_mod, "api_request", new=api):
            await monitor.tick(self._results(True))
        self.assertEqual(api.await_args[0][1:], ("GET", "/api/v1/status"))
        self.assertEqual(api.await_args[1]["base"], "http://[fd00:1::3]:42")


class MonitorTickTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.settings = make_settings(fall=2, rise=2)
        self.state = HealthState()
        self.metrics = Metrics()
        self.actions = mock.MagicMock()
        self.actions.ensure_failover = mock.AsyncMock()
        self.actions.ensure_fallback = mock.AsyncMock()
        self.monitor = Monitor(self.settings, self.state, self.metrics, self.actions)

    @staticmethod
    def _results(ok: bool) -> dict[str, bool]:
        return {t: ok for t in ("1.1.1.1", "8.8.8.8", "2606::1", "2001::8")}

    async def test_fall_then_rise(self) -> None:
        get = self.metrics.registry.get_sample_value
        await self.monitor.tick(self._results(False))
        self.assertTrue(self.state.healthy)
        self.actions.ensure_fallback.assert_awaited()
        await self.monitor.tick(self._results(False))
        self.assertFalse(self.state.healthy)
        self.actions.ensure_failover.assert_awaited()
        self.assertEqual(get("wan_healthcheck_failovers_total"), 1)
        self.assertEqual(get("wan_healthcheck_healthy"), 0)
        await self.monitor.tick(self._results(True))
        await self.monitor.tick(self._results(True))
        self.assertTrue(self.state.healthy)
        self.assertEqual(get("wan_healthcheck_fallbacks_total"), 1)
        self.assertEqual(
            get("wan_healthcheck_rounds_total", {"result": "unhealthy"}), 2
        )
        self.assertEqual(get("wan_healthcheck_rounds_total", {"result": "healthy"}), 2)

    async def test_heartbeat_is_rate_limited(self) -> None:
        with self.assertLogs(monitor_mod.LOG, level="INFO") as logs:
            for _ in range(5):
                await self.monitor.tick(self._results(True))
        beats = [r for r in logs.records if "heartbeat:" in r.getMessage()]
        self.assertEqual(len(beats), 1, "one beat, not one per tick")
        self.assertIn("att HEALTHY (armed)", beats[0].getMessage())
        self.assertIn("ipv4=0%failing", beats[0].getMessage())

    async def test_heartbeat_repeats_after_interval(self) -> None:
        self.monitor.settings = make_settings(heartbeat_s=0.001)
        with self.assertLogs(monitor_mod.LOG, level="INFO") as logs:
            await self.monitor.tick(self._results(True))
            await asyncio.sleep(0.002)
            await self.monitor.tick(self._results(True))
        beats = [r for r in logs.records if "heartbeat:" in r.getMessage()]
        self.assertEqual(len(beats), 2)

    async def test_heartbeat_disabled_by_zero(self) -> None:
        self.monitor.settings = make_settings(heartbeat_s=0)
        with self.assertLogs(monitor_mod.LOG, level="INFO") as logs:
            await self.monitor.tick(self._results(True))
            LOG_MARKER = "marker so assertLogs has a record"
            monitor_mod.LOG.info(LOG_MARKER)
        self.assertEqual(
            [r for r in logs.records if "heartbeat:" in r.getMessage()], []
        )

    async def test_heartbeat_reports_degraded_and_dry_run(self) -> None:
        self.monitor.settings = make_settings(dry_run=True, fall=1)
        with self.assertLogs(monitor_mod.LOG, level="INFO") as logs:
            await self.monitor.tick(self._results(False))
        beat = next(r for r in logs.records if "heartbeat:" in r.getMessage())
        self.assertIn("att DEGRADED (report-only)", beat.getMessage())
        self.assertIn("ipv4=100%failing", beat.getMessage())

    async def test_forced_state_wins_over_healthy_probes(self) -> None:
        self.state.forced_failover = True
        await self.monitor.tick(self._results(True))
        self.actions.ensure_failover.assert_awaited()
        self.actions.ensure_fallback.assert_not_awaited()
