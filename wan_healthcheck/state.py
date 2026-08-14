"""The health verdict, its hysteresis, and the peer gate."""

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .probe import family_failing_pct, family_results, group_by_family


@dataclass
class HealthState:
    healthy: bool = True
    forced_failover: bool = False
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    last_change: float = field(default_factory=time.time)
    probe_results: dict[str, bool] = field(default_factory=dict)
    # Track file mtime, refreshed each tick - durable across daemon restarts.
    state_since: float = field(default_factory=time.time)
    # Peer (backup router) health. Defaults True so that with no peer
    # configured the gate is transparent and behaviour is unchanged.
    peer_healthy: bool = True
    peer_reachable: bool = True
    peer_checked: bool = False
    consecutive_peer_failures: int = 0

    @property
    def failed_over(self) -> bool:
        """Whether traffic should be on the backup router.

        Gated on the peer: failing over to a backup that has no working
        internet makes an outage worse, not better - it just moves everyone
        onto a second dead path. A forced failover bypasses the gate, since
        that is an operator saying "do it anyway".
        """
        if self.forced_failover:
            return True
        return not self.healthy and self.peer_healthy

    @property
    def failover_suppressed(self) -> bool:
        """WAN is degraded but we are staying put because the peer is no
        better. Worth surfacing - it looks identical to "healthy" otherwise."""
        return not self.healthy and not self.peer_healthy

    def record_round(self, round_ok: bool, fall: int, rise: int) -> bool:
        """Fold one probe round into the hysteresis counters; True on a
        verdict transition."""
        if round_ok:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
        if self.healthy and self.consecutive_failures >= fall:
            self.healthy = False
            self.last_change = time.time()
            return True
        if not self.healthy and self.consecutive_successes >= rise:
            self.healthy = True
            self.last_change = time.time()
            return True
        return False

    def snapshot(self, family_fail_pct: float) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "forced_failover": self.forced_failover,
            "failed_over": self.failed_over,
            "consecutive_successes": self.consecutive_successes,
            "consecutive_failures": self.consecutive_failures,
            "last_change": self.last_change,
            "last_change_iso": datetime.fromtimestamp(self.last_change).isoformat(),
            "probe_results": dict(self.probe_results),
            "family_results": family_results(self.probe_results, family_fail_pct),
            "family_failing_pct": {
                family: family_failing_pct(oks)
                for family, oks in group_by_family(self.probe_results).items()
            },
            "family_fail_pct": family_fail_pct,
            "peer_healthy": self.peer_healthy,
            "peer_reachable": self.peer_reachable,
            "peer_checked": self.peer_checked,
            "failover_suppressed": self.failover_suppressed,
            "state_since": self.state_since,
            "state_since_iso": datetime.fromtimestamp(self.state_since).isoformat(),
        }
