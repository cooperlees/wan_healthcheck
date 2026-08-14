"""Prometheus metrics."""

import time

from prometheus_client import CollectorRegistry, Counter, Gauge

from .probe import family_failing_pct, family_name, family_results, group_by_family
from .state import HealthState


class Metrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.healthy = Gauge(
            "wan_healthcheck_healthy",
            "1 while the WAN probe verdict is healthy",
            registry=self.registry,
        )
        self.forced = Gauge(
            "wan_healthcheck_forced",
            "1 while failover is forced via the REST API",
            registry=self.registry,
        )
        self.failed_over = Gauge(
            "wan_healthcheck_failed_over",
            "1 while traffic is failed over to the backup router, whether "
            "from the probe verdict or a forced override; this is the state "
            "to alert on",
            registry=self.registry,
        )
        self.dry_run = Gauge(
            "wan_healthcheck_dry_run",
            "1 when running in dry-run (observe-only) mode",
            registry=self.registry,
        )
        self.probe_success = Gauge(
            "wan_healthcheck_probe_success",
            "Last probe-round result per target",
            ["target", "family"],
            registry=self.registry,
        )
        self.family_healthy = Gauge(
            "wan_healthcheck_family_healthy",
            "1 while this address family is below its failure threshold; a "
            "family dropping to 0 is what makes a round unhealthy",
            ["family"],
            registry=self.registry,
        )
        self.family_failing_pct = Gauge(
            "wan_healthcheck_family_failing_pct",
            "Share of this address family's targets failing, 0-100",
            ["family"],
            registry=self.registry,
        )
        self.peer_healthy = Gauge(
            "wan_healthcheck_peer_healthy",
            "1 while the backup router reports a healthy WAN; failover is "
            "gated on this. 1 when no peer is configured",
            registry=self.registry,
        )
        self.peer_reachable = Gauge(
            "wan_healthcheck_peer_reachable",
            "1 while the backup router's status API answers",
            registry=self.registry,
        )
        self.failover_suppressed = Gauge(
            "wan_healthcheck_failover_suppressed",
            "1 while this WAN is degraded but failover is being held back "
            "because the backup router is no better",
            registry=self.registry,
        )
        self.family_fail_pct_threshold = Gauge(
            "wan_healthcheck_family_fail_pct_threshold",
            "Configured share of a family's targets that must fail before "
            "the family counts as down",
            registry=self.registry,
        )
        self.consecutive_successes = Gauge(
            "wan_healthcheck_consecutive_successes",
            "Consecutive healthy probe rounds",
            registry=self.registry,
        )
        self.consecutive_failures = Gauge(
            "wan_healthcheck_consecutive_failures",
            "Consecutive unhealthy probe rounds",
            registry=self.registry,
        )
        self.rounds = Counter(
            "wan_healthcheck_rounds",
            "Probe rounds by result",
            ["result"],
            registry=self.registry,
        )
        self.failovers = Counter(
            "wan_healthcheck_failovers",
            "Transitions into the failed-over state",
            registry=self.registry,
        )
        self.fallbacks = Counter(
            "wan_healthcheck_fallbacks",
            "Transitions back to the normal state",
            registry=self.registry,
        )
        self.last_state_change = Gauge(
            "wan_healthcheck_last_state_change_timestamp_seconds",
            "Unix time the failover state was last set, from the track "
            "file's mtime; survives daemon restarts, resets at boot",
            registry=self.registry,
        )
        self.start_time = Gauge(
            "wan_healthcheck_start_timestamp_seconds",
            "Unix time this daemon process started",
            registry=self.registry,
        )

    def observe_state(self, state: HealthState, family_fail_pct: float) -> None:
        self.healthy.set(1 if state.healthy else 0)
        self.forced.set(1 if state.forced_failover else 0)
        self.failed_over.set(1 if state.failed_over else 0)
        self.peer_healthy.set(1 if state.peer_healthy else 0)
        self.peer_reachable.set(1 if state.peer_reachable else 0)
        self.failover_suppressed.set(1 if state.failover_suppressed else 0)
        self.consecutive_successes.set(state.consecutive_successes)
        self.consecutive_failures.set(state.consecutive_failures)
        for target, ok in state.probe_results.items():
            self.probe_success.labels(target=target, family=family_name(target)).set(
                1 if ok else 0
            )
        for family, ok in family_results(state.probe_results, family_fail_pct).items():
            self.family_healthy.labels(family=family).set(1 if ok else 0)
        for family, oks in group_by_family(state.probe_results).items():
            self.family_failing_pct.labels(family=family).set(family_failing_pct(oks))

    def observe_effective_change(self, now_failed_over: bool) -> None:
        if now_failed_over:
            self.failovers.inc()
        else:
            self.fallbacks.inc()
