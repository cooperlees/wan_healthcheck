"""The tick loop: probe, decide, act, repeat."""

import time

from .actions import Actions
from .config import Settings
from .keepalived import state_since
from .log import LOG
from .metrics import Metrics
from .probe import family_failing_pct, group_by_family, probe_round, round_verdict
from .server import api_request
from .state import HealthState


class Monitor:
    def __init__(
        self,
        settings: Settings,
        state: HealthState,
        metrics: Metrics,
        actions: Actions,
    ) -> None:
        self.settings = settings
        self.state = state
        self.metrics = metrics
        self.actions = actions
        self._last_heartbeat = 0.0

    def _maybe_heartbeat(self, results: dict[str, bool], now: float) -> None:
        """Periodic liveness line.

        Without this the daemon is silent for days at a time - correct, but it
        makes a log panel indistinguishable from a broken one, and gives no
        way to confirm from logs alone that probing is still happening.
        """
        if self.settings.heartbeat_s <= 0:
            return
        if now - self._last_heartbeat < self.settings.heartbeat_s:
            return
        self._last_heartbeat = now
        families = " ".join(
            f"{family}={family_failing_pct(oks):.0f}%failing"
            for family, oks in sorted(group_by_family(results).items())
        )
        peer = ""
        if self.settings.peer_url:
            peer = " peer={}".format(
                "healthy" if self.state.peer_healthy else "UNHEALTHY"
            )
        LOG.info(
            "heartbeat: %s %s (%s) ok_streak=%d fail_streak=%d %s%s",
            self.settings.interface or "WAN",
            "HEALTHY" if self.state.healthy else "DEGRADED",
            "report-only" if self.settings.dry_run else "armed",
            self.state.consecutive_successes,
            self.state.consecutive_failures,
            families,
            peer,
        )

    async def _refresh_peer(self) -> None:
        """Ask the backup router whether its own WAN is healthy.

        Polled rather than pushed: it reuses the peer's existing status
        endpoint, needs no state or staleness handling here, and an
        unreachable peer reads as "not a viable failover target", which is
        the safe answer. The peer's verdict is already hysteresis-smoothed by
        its own fall/rise, so it is trusted directly; only the transport is
        tolerated for `fall` consecutive failures, to ride out a blip.
        """
        if not self.settings.peer_url:
            return
        self.state.peer_checked = True
        reply = await api_request(
            self.settings, "GET", "/api/v1/status", base=self.settings.peer_url
        )
        if reply is None:
            self.state.consecutive_peer_failures += 1
            self.state.peer_reachable = False
        else:
            self.state.consecutive_peer_failures = 0
            self.state.peer_reachable = True
        was_healthy = self.state.peer_healthy
        if reply is not None:
            # A peer that has itself failed over is still a valid target: it
            # means *it* moved traffic somewhere, not that it lacks internet.
            self.state.peer_healthy = bool(reply.get("healthy", False))
        elif self.state.consecutive_peer_failures >= self.settings.fall:
            self.state.peer_healthy = False
        if was_healthy != self.state.peer_healthy:
            LOG.warning(
                "Peer %s is now %s",
                self.settings.peer_url,
                "HEALTHY" if self.state.peer_healthy else "UNHEALTHY",
            )

    async def tick(self, results: dict[str, bool] | None = None) -> None:
        await self._refresh_peer()
        if results is None:
            results = await probe_round(self.settings)
        self.state.probe_results = results
        round_ok = round_verdict(results, self.settings.family_fail_pct)
        self.metrics.rounds.labels(result="healthy" if round_ok else "unhealthy").inc()
        was_failed_over = self.state.failed_over
        if self.state.record_round(round_ok, self.settings.fall, self.settings.rise):
            LOG.warning(
                "WAN verdict transition: now %s (probe results: %s)",
                "HEALTHY" if self.state.healthy else "DEGRADED",
                results,
            )
            if self.state.failover_suppressed:
                LOG.warning(
                    "Holding position: %s is degraded but peer %s is not "
                    "healthy either, so failing over would not help",
                    self.settings.interface or "WAN",
                    self.settings.peer_url,
                )
        if self.state.failed_over != was_failed_over:
            self.metrics.observe_effective_change(self.state.failed_over)
        self.metrics.observe_state(self.state, self.settings.family_fail_pct)
        # Refreshed every tick rather than only on transition: the mtime is
        # the source of truth, and this keeps the gauge from ever sitting at
        # 0 (which reads as "1970" - i.e. 57 years - on a dashboard).
        self.state.state_since = state_since(
            self.settings.track_file, self.state.last_change
        )
        self.metrics.last_state_change.set(self.state.state_since)
        self._maybe_heartbeat(results, time.time())
        if self.state.failed_over:
            await self.actions.ensure_failover()
        else:
            await self.actions.ensure_fallback()
