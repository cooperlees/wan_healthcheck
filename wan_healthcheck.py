#!/usr/bin/env python3
"""Fail a LAN over to a backup router when the WAN degrades but stays up.

The case this exists for is a WAN that keeps its DHCP lease - so the kernel
default route is still sitting there looking healthy - while no traffic
actually reaches the internet. Link-state and route-presence checks cannot
see it.

This daemon routes nothing itself. It probes the WAN and, on sustained
failure, flips three switches so that other software moves traffic:

  1. stops systemd-networkd's IPv6 Router Advertisements, by dropping
     IPv6SendRA=no into networkd's drop-in directory - which also gets
     networkd's own graceful lifetime-0 shutdown advert for free,
  2. sends deprecation RAs so the WAN-derived prefix goes preferred-0 and
     clients stop sourcing from an address whose uplink is dead,
  3. writes 1 to a file keepalived is watching, dropping this router's VRRP
     priority below the backup's so the IPv4 gateway VIP moves.

All three reverse automatically once the WAN is healthy again, with
deliberately asymmetric hysteresis. Failover is also gated on the backup
router reporting a healthy WAN of its own, since moving clients onto an
equally dead path makes an outage worse.

See README.md for what has to be set up for any of this to work.
"""

import asyncio
import json
import logging
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv6Address, IPv6Network, ip_address
from pathlib import Path
from typing import Any, Final

import click
from aiohttp import ClientError, ClientSession, ClientTimeout, web
from mypy_extensions import mypyc_attr
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    generate_latest,
)
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

LOG: Final[logging.Logger] = logging.getLogger("wan_healthcheck")

PROC_IF_INET6: Final[Path] = Path("/proc/net/if_inet6")
ALL_NODES_MULTICAST: Final[str] = "ff02::1"
DEFAULT_DROPIN_ROOT: Final[Path] = Path("/run/systemd/network")
# RFC 4862 clients clamp a received valid lifetime < 2h up to 2h anyway,
# so 7200 is the effective floor; preferred=0 is what actually deprecates.
DEPRECATION_VALID_LIFETIME: Final[int] = 7200
DEPRECATION_BURSTS: Final[int] = 3
DEPRECATION_BURST_GAP_S: Final[float] = 1.0


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


@dataclass(frozen=True)
class Settings:
    """All tunables; populated from the click group options."""

    interface: str
    targets_v4: tuple[str, ...]
    targets_v6: tuple[str, ...]
    interval_s: float
    fall: int
    rise: int
    family_fail_pct: float
    heartbeat_s: float
    ra_interfaces: tuple[str, ...]
    track_file: Path
    dropin_root: Path
    port: int
    api_url: str
    peer_url: str
    dry_run: bool

    @property
    def targets(self) -> tuple[str, ...]:
        return self.targets_v4 + self.targets_v6


def _parse_if_inet6_line(line: str) -> tuple[IPv6Address, int, int, str] | None:
    """One /proc/net/if_inet6 line -> (address, prefixlen, scope, ifname)."""
    fields = line.split()
    if len(fields) != 6:
        return None
    raw, _ifindex, prefixlen_hex, scope_hex, _flags, ifname = fields
    try:
        address = IPv6Address(int(raw, 16))
        return address, int(prefixlen_hex, 16), int(scope_hex, 16), ifname
    except ValueError:
        return None


def prefixes_for_interface(
    interface: str, proc_path: Path = PROC_IF_INET6
) -> list[IPv6Network]:
    """Global-scope /64s on `interface` (the prefixes networkd advertises)."""
    prefixes: list[IPv6Network] = []
    for line in proc_path.read_text().splitlines():
        parsed = _parse_if_inet6_line(line)
        if parsed is None:
            continue
        address, _prefixlen, scope, ifname = parsed
        if ifname != interface or scope != 0:
            continue
        if not address.is_global:
            continue
        network = IPv6Network((address, 64), strict=False)
        if network not in prefixes:
            prefixes.append(network)
    return prefixes


def link_locals_for_interface(
    interface: str, proc_path: Path = PROC_IF_INET6
) -> list[IPv6Address]:
    """Link-local addresses on `interface`, excluding /128s (keepalived VIPs).

    networkd's RA source is one of the interface's link-locals; rather than
    guess which, deprecation RAs are sent from each candidate (deprecating a
    router entry clients never saw is a no-op). The fe80::1/128 VRRP VIP is
    excluded: post-failover it belongs to the backup router and stays live.
    """
    addresses: list[IPv6Address] = []
    for line in proc_path.read_text().splitlines():
        parsed = _parse_if_inet6_line(line)
        if parsed is None:
            continue
        address, prefixlen, scope, ifname = parsed
        if ifname != interface or scope != 0x20 or prefixlen == 128:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def build_router_advert(
    prefixes: Sequence[IPv6Network],
    valid_lifetime: int = DEPRECATION_VALID_LIFETIME,
) -> bytes:
    """Deprecation RA: router lifetime 0, each prefix preferred-lifetime 0.

    Checksum is left zeroed; the kernel fills it for IPPROTO_ICMPV6 raw sockets.
    """
    packet = ICMPv6ND_RA(routerlifetime=0, cksum=0)
    for prefix in prefixes:
        packet = packet / ICMPv6NDOptPrefixInfo(
            prefix=str(prefix.network_address),
            prefixlen=prefix.prefixlen,
            L=1,
            A=1,
            validlifetime=valid_lifetime,
            preferredlifetime=0,
        )
    return bytes(packet)


def send_ra_packet(
    packet: bytes, interface: str, source: IPv6Address
) -> None:
    """Transmit a raw ICMPv6 RA to all-nodes on `interface`."""
    ifindex = socket.if_nametoindex(interface)
    with socket.socket(
        socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6
    ) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.bind((str(source), 0, 0, ifindex))
        sock.sendto(packet, (ALL_NODES_MULTICAST, 0, 0, ifindex))


@mypyc_attr(native_class=False)
class NetworkdError(RuntimeError):
    pass


@mypyc_attr(native_class=False)
class ApiError(RuntimeError):
    pass


DROPIN_NAME: Final[str] = "wan_healthcheck.conf"
# Stopping RA this way makes networkd emit its own graceful RFC 4861
# shutdown advert (router lifetime 0) and then fall silent, which is what
# lets our deprecation RA stick - see send_deprecation_ras().
DROPIN_BODY: Final[str] = "# Written by wan_healthcheck\n[Network]\nIPv6SendRA=no\n"


def _networkctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["networkctl", *args], capture_output=True, text=True
    )


def network_file_for(interface: str) -> Path:
    """The .network file networkd applied to this link.

    Read structurally from `networkctl --json`, not by scraping the human
    output, so drop-ins land beside the right file even if the numbering
    changes.
    """
    result = _networkctl("--json=short", "status", interface)
    if result.returncode != 0:
        raise NetworkdError(
            f"networkctl status {interface} failed: {result.stderr.strip()}"
        )
    path = json.loads(result.stdout).get("NetworkFile")
    if not path:
        raise NetworkdError(f"{interface} has no NetworkFile (unmanaged?)")
    return Path(path)


def dropin_path(interface: str, dropin_root: Path) -> Path:
    """Where our drop-in goes for `interface`.

    Under /run rather than /etc so it is tmpfs-backed: a reboot wipes it and
    RAs resume, keeping the whole mechanism fail-open. The directory itself
    is pre-created (owned by this daemon's user) by tmpfiles.d, since
    /run/systemd/network is root-owned and the daemon is not root.
    """
    return dropin_root / f"{network_file_for(interface).name}.d" / DROPIN_NAME


def apply_networkd(interfaces: Sequence[str]) -> None:
    """Make networkd pick up drop-in changes for these links."""
    reload_result = _networkctl("reload")
    if reload_result.returncode != 0:
        raise NetworkdError(
            f"networkctl reload failed: {reload_result.stderr.strip()}"
        )
    result = _networkctl("reconfigure", *interfaces)
    if result.returncode != 0:
        raise NetworkdError(
            f"networkctl reconfigure failed: {result.stderr.strip()}"
        )


def state_since(track_file: Path, fallback: float) -> float:
    """When the failover state was last set, from the track file's mtime.

    Better than an in-process timestamp: the file is only rewritten when the
    value actually changes, so its mtime *is* the last transition - and it
    survives daemon restarts, which an in-process value does not (every
    ansible_shed redeploy would otherwise reset the clock). It lives on
    tmpfs, so a reboot correctly resets it to the tmpfiles.d creation time.
    """
    try:
        return track_file.stat().st_mtime
    except OSError:
        return fallback


def write_track_file(path: Path, value: int) -> bool:
    """Atomically write keepalived's track_file; returns True if it changed.

    Compared stripped, not byte-for-byte: systemd-tmpfiles seeds the file as
    a bare "0" with no trailing newline, so an exact match would rewrite it
    on the first armed tick purely over whitespace - bumping the mtime that
    state_since() reads and making it look like a transition happened.
    """
    text = f"{value}\n"
    try:
        if path.read_text().strip() == str(value):
            return False
    except OSError:
        pass
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    tmp.replace(path)
    return True


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
            "state_since_iso": datetime.fromtimestamp(
                self.state_since
            ).isoformat(),
        }


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
            self.probe_success.labels(
                target=target, family=family_name(target)
            ).set(1 if ok else 0)
        for family, ok in family_results(
            state.probe_results, family_fail_pct
        ).items():
            self.family_healthy.labels(family=family).set(1 if ok else 0)
        for family, oks in group_by_family(state.probe_results).items():
            self.family_failing_pct.labels(family=family).set(
                family_failing_pct(oks)
            )

    def observe_effective_change(self, now_failed_over: bool) -> None:
        if now_failed_over:
            self.failovers.inc()
        else:
            self.fallbacks.inc()


class Actions:
    """Applies/reverses the failover side effects, idempotently.

    RA suppression is done by dropping a `IPv6SendRA=no` file into networkd's
    drop-in directory rather than by firewalling the packets. Blocking them in
    nftables' OUTPUT hook returns EPERM to networkd, which makes sd-radv stop
    its RA timer permanently and silently - it never resumes, so IPv6 could
    not fail back. Letting networkd stop on purpose also gets its own graceful
    RFC 4861 shutdown advert (router lifetime 0) for free.

    In dry-run nothing is executed - every action is logged as "would ...".
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # Dry-run has no state to diff against, so intent is tracked here to
        # keep the monitor loop from logging the same line every tick.
        self._last_dry_intent: str | None = None

    def _dropins(self) -> list[Path]:
        return [
            dropin_path(interface, self._settings.dropin_root)
            for interface in self._settings.ra_interfaces
        ]

    async def _send_deprecation_ras(self) -> None:
        """Deprecate the advertised prefixes (preferred lifetime 0).

        networkd's own shutdown advert withdraws this box as a *router* but
        carries no prefix information, so clients keep the WAN-derived prefix
        as preferred. Only rule 3 of RFC 6724 (avoid deprecated addresses) is
        mandatory in every stack; rule 5.5 (prefer the next hop's prefix) is
        optional and, measured, macOS implements it while Linux does not. So
        this is what makes every client move off the dead prefix uniformly.

        Sent *after* networkd has gone quiet - otherwise its next scheduled
        advert would re-advertise the prefix at its normal lifetime and undo
        the deprecation within seconds.
        """
        s = self._settings
        for burst in range(DEPRECATION_BURSTS):
            for interface in s.ra_interfaces:
                prefixes = prefixes_for_interface(interface)
                packet = build_router_advert(prefixes)
                for source in link_locals_for_interface(interface):
                    try:
                        send_ra_packet(packet, interface, source)
                    except OSError as exc:
                        LOG.error(
                            "Failed to send deprecation RA on %s from %s: %s",
                            interface,
                            source,
                            exc,
                        )
                LOG.info(
                    "Sent deprecation RA burst %d/%d on %s (%d prefixes)",
                    burst + 1,
                    DEPRECATION_BURSTS,
                    interface,
                    len(prefixes),
                )
            if burst + 1 < DEPRECATION_BURSTS:
                await asyncio.sleep(DEPRECATION_BURST_GAP_S)

    async def ensure_failover(self) -> None:
        s = self._settings
        if s.dry_run:
            if self._last_dry_intent != "failover":
                LOG.warning(
                    "DRY-RUN: would stop RAs on %s via networkd drop-ins, "
                    "send deprecation RAs, and write 1 to %s",
                    ",".join(s.ra_interfaces),
                    s.track_file,
                )
                self._last_dry_intent = "failover"
            return
        missing = [path for path in self._dropins() if not path.exists()]
        if missing:
            for path in missing:
                path.write_text(DROPIN_BODY)
            try:
                apply_networkd(s.ra_interfaces)
            except NetworkdError:
                # Roll the files back, or the next tick sees nothing missing
                # and assumes the job is done - leaving drop-ins on disk that
                # networkd never read, so IPv4 fails over and IPv6 does not.
                for path in missing:
                    path.unlink(missing_ok=True)
                raise
            LOG.warning(
                "Stopped RAs on %s (networkd sent its lifetime-0 withdrawal)",
                ",".join(s.ra_interfaces),
            )
            await self._send_deprecation_ras()
        if write_track_file(s.track_file, 1):
            LOG.warning(
                "Wrote 1 to %s (keepalived VRRP priority drops)", s.track_file
            )

    async def ensure_fallback(self) -> None:
        s = self._settings
        if s.dry_run:
            if self._last_dry_intent != "fallback":
                LOG.info(
                    "DRY-RUN: would remove networkd drop-ins on %s and write "
                    "0 to %s",
                    ",".join(s.ra_interfaces),
                    s.track_file,
                )
                self._last_dry_intent = "fallback"
            return
        present = [path for path in self._dropins() if path.exists()]
        if present:
            for path in present:
                path.unlink()
            apply_networkd(s.ra_interfaces)
            LOG.warning(
                "Resumed RAs on %s", ",".join(s.ra_interfaces)
            )
        if write_track_file(s.track_file, 0):
            LOG.warning(
                "Wrote 0 to %s (keepalived VRRP priority restored)", s.track_file
            )


async def probe_target(interface: str, target: str) -> bool:
    """One target probe: 3 pings; >=1 reply = healthy.

    An empty `interface` probes over whatever route the host would normally
    use, rather than pinning to one link. That is the right question for a
    backup router being asked "do you have working internet at all" - pinning
    to its primary WAN would report it dead whenever that link is down, even
    though it has another path it would happily use.
    """
    bind = ["-I", interface] if interface else []
    process = await asyncio.create_subprocess_exec(
        "ping",
        "-c",
        "3",
        "-i",
        "0.3",
        "-W",
        "2",
        *bind,
        target,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        returncode = await asyncio.wait_for(process.wait(), timeout=15.0)
    except TimeoutError:
        process.kill()
        await process.wait()
        return False
    return returncode == 0


async def probe_round(settings: Settings) -> dict[str, bool]:
    results = await asyncio.gather(
        *(probe_target(settings.interface, target) for target in settings.targets)
    )
    return dict(zip(settings.targets, results, strict=True))


def family_name(target: str) -> str:
    """Address family of a target, as a metric label. Anything unparseable
    (e.g. a hostname) becomes its own family rather than crashing the round."""
    try:
        return f"ipv{ip_address(target).version}"
    except ValueError:
        return "other"


def group_by_family(results: dict[str, bool]) -> dict[str, list[bool]]:
    """Probe results bucketed by address family."""
    families: dict[str, list[bool]] = {}
    for target, ok in results.items():
        families.setdefault(family_name(target), []).append(ok)
    return families


def family_failing_pct(oks: Sequence[bool]) -> float:
    """Share of a family's targets that failed, 0-100."""
    if not oks:
        return 0.0
    return 100.0 * sum(1 for ok in oks if not ok) / len(oks)


def family_results(
    results: dict[str, bool], fail_pct: float
) -> dict[str, bool]:
    """Per-family liveness: a family is down once the failing share of its
    targets reaches `fail_pct`. Compared as `failing * 100 >= pct * total` to
    keep the boundary exact rather than at the mercy of float division."""
    families: dict[str, bool] = {}
    for family, oks in group_by_family(results).items():
        failing = sum(1 for ok in oks if not ok)
        families[family] = not (failing * 100 >= fail_pct * len(oks))
    return families


def round_verdict(results: dict[str, bool], fail_pct: float) -> bool:
    """Round healthy = no address family has crossed its failure threshold.

    Judged per family rather than as one flat majority across all targets.
    The targets split evenly across IPv4 and IPv6, so a family-wide outage
    (the WAN's v6 breaking while v4 stays up) is exactly half - it sits
    on a flat majority rule's tolerance boundary and never trips it, despite
    being precisely what the RA suppression exists to handle.

    `fail_pct` sets how much of a family must fail before it counts as down.
    At the default 100 every target in the family must fail, which still
    absorbs a single provider's outage: Cloudflare going away leaves Google
    answering in both families. Lower it to trade that tolerance for speed.
    """
    if not results:
        return False
    return all(family_results(results, fail_pct).values())


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
        reply = await _api_request(
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
        self.metrics.rounds.labels(
            result="healthy" if round_ok else "unhealthy"
        ).inc()
        was_failed_over = self.state.failed_over
        if self.state.record_round(
            round_ok, self.settings.fall, self.settings.rise
        ):
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
        self.metrics.observe_state(
            self.state, self.settings.family_fail_pct
        )
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


def make_app(monitor: Monitor) -> web.Application:
    async def metrics_handler(request: web.Request) -> web.Response:
        return web.Response(
            body=generate_latest(monitor.metrics.registry),
            headers={"Content-Type": CONTENT_TYPE_LATEST},
        )

    def status_body() -> dict[str, Any]:
        body = monitor.state.snapshot(monitor.settings.family_fail_pct)
        body["dry_run"] = monitor.settings.dry_run
        body["interface"] = monitor.settings.interface
        return body

    async def status_handler(request: web.Request) -> web.Response:
        return web.json_response(status_body())

    async def failover_handler(request: web.Request) -> web.Response:
        was = monitor.state.failed_over
        monitor.state.forced_failover = True
        if monitor.state.failed_over != was:
            monitor.metrics.observe_effective_change(True)
        LOG.warning("Forced failover requested via API")
        await monitor.actions.ensure_failover()
        monitor.metrics.observe_state(
            monitor.state, monitor.settings.family_fail_pct
        )
        return web.json_response(status_body())

    async def fallback_handler(request: web.Request) -> web.Response:
        was = monitor.state.failed_over
        monitor.state.forced_failover = False
        if monitor.state.failed_over != was:
            monitor.metrics.observe_effective_change(False)
        LOG.warning(
            "Forced failover cleared via API (probe verdict: %s)",
            "healthy" if monitor.state.healthy else "degraded",
        )
        if not monitor.state.failed_over:
            await monitor.actions.ensure_fallback()
        monitor.metrics.observe_state(
            monitor.state, monitor.settings.family_fail_pct
        )
        return web.json_response(status_body())

    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/api/v1/status", status_handler)
    app.router.add_post("/api/v1/failover", failover_handler)
    app.router.add_post("/api/v1/fallback", fallback_handler)
    return app


async def run_monitor(settings: Settings) -> int:
    state = HealthState()
    # Inherit prior state across daemon restarts (Restart=on-failure must not
    # flap a live failover back and forth).
    try:
        if settings.track_file.read_text().strip() == "1":
            state.healthy = False
            LOG.warning(
                "Starting in DEGRADED state (inherited from %s)",
                settings.track_file,
            )
    except OSError:
        pass
    metrics = Metrics()
    metrics.dry_run.set(1 if settings.dry_run else 0)
    metrics.family_fail_pct_threshold.set(settings.family_fail_pct)
    metrics.start_time.set(time.time())
    metrics.last_state_change.set(
        state_since(settings.track_file, state.last_change)
    )
    monitor = Monitor(settings, state, metrics, Actions(settings))

    # access_log=None: prometheus scrapes /metrics every 15s, and an access
    # line per scrape is ~5.7k journal lines a day of pure noise.
    runner = web.AppRunner(make_app(monitor), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "::", settings.port)
    await site.start()
    LOG.info(
        "Monitoring %s every %.0fs (fall=%d rise=%d family_fail_pct=%g "
        "targets=%s); API/metrics on [::]:%d%s",
        settings.interface,
        settings.interval_s,
        settings.fall,
        settings.rise,
        settings.family_fail_pct,
        ",".join(settings.targets),
        settings.port,
        " [DRY-RUN]" if settings.dry_run else "",
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        while not stop.is_set():
            started = time.monotonic()
            try:
                await monitor.tick()
            except Exception as exc:  # daemon must survive transient errors
                LOG.error("Monitor tick failed: %s", exc)
            elapsed = time.monotonic() - started
            delay = max(0.0, settings.interval_s - elapsed)
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                pass
    finally:
        await runner.cleanup()
    # Deliberately leave drop-ins + track file untouched on shutdown: stopping
    # the daemon mid-outage must not silently un-fail-over.
    LOG.info("Shutting down (leaving current failover state as-is)")
    return 0


async def _api_request(
    settings: Settings, method: str, path: str, base: str | None = None
) -> dict[str, Any] | None:
    """Returns the JSON reply, or None if unreachable.

    `base` targets a different daemon (the peer); it defaults to our own API.
    """
    root = base if base is not None else settings.api_url
    try:
        async with ClientSession(timeout=ClientTimeout(total=3)) as session:
            async with session.request(method, f"{root}{path}") as response:
                if response.status != 200:
                    raise ApiError(
                        f"daemon API returned HTTP {response.status} for {path}"
                    )
                body: dict[str, Any] = await response.json()
                return body
    except (ClientError, OSError):
        return None


async def _oneshot(settings: Settings, action: str) -> int:
    """failover/fallback: prefer the running daemon's API (so one-shots never
    fight the monitor loop); act directly only when the daemon is down."""
    if settings.dry_run:
        actions = Actions(settings)
        if action == "failover":
            await actions.ensure_failover()
        else:
            await actions.ensure_fallback()
        return 0
    reply = await _api_request(settings, "POST", f"/api/v1/{action}")
    if reply is not None:
        LOG.info("Daemon accepted %s: %s", action, json.dumps(reply))
        return 0
    LOG.warning("Daemon API unreachable at %s; acting directly", settings.api_url)
    actions = Actions(settings)
    if action == "failover":
        await actions.ensure_failover()
    else:
        await actions.ensure_fallback()
    return 0


@click.group(invoke_without_command=True)
@click.option("--dry-run", is_flag=True, help="Log actions without executing.")
@click.option(
    "--interface",
    default="",
    show_default=True,
    help="WAN interface to pin probes to with ping -I. Empty means probe "
    "over whatever route the host would normally use, which is what a backup "
    "router wants: 'do I have internet at all', not 'is one link up'.",
)
@click.option(
    "--target-v4",
    "targets_v4",
    multiple=True,
    default=("1.1.1.1", "8.8.8.8"),
    show_default=True,
)
@click.option(
    "--target-v6",
    "targets_v6",
    multiple=True,
    default=("2606:4700:4700::1111", "2001:4860:4860::8888"),
    show_default=True,
)
@click.option("--interval", "interval_s", default=5.0, show_default=True)
@click.option("--fall", default=6, show_default=True)
@click.option("--rise", default=60, show_default=True)
@click.option(
    "--heartbeat-s",
    default=300.0,
    show_default=True,
    help="Seconds between liveness log lines; 0 disables. The daemon is "
    "otherwise silent while healthy, which makes a log view look broken.",
)
@click.option(
    "--family-fail-pct",
    type=click.FloatRange(0, 100, min_open=True),
    default=100.0,
    show_default=True,
    help="Percent of an address family's targets that must fail before that "
    "family counts as down. 100 = every target in the family.",
)
@click.option(
    "--ra-interface",
    "ra_interfaces",
    multiple=True,
    default=(),
    show_default=True,
    help="LAN interface to stop advertising on. Repeatable; required for the\n"
    "IPv6 half of a failover to do anything.",
)
@click.option(
    "--track-file",
    type=click.Path(path_type=Path),
    default=Path("/run/wan_healthcheck/wan_weight"),
    show_default=True,
)
@click.option(
    "--dropin-root",
    type=click.Path(path_type=Path),
    default=DEFAULT_DROPIN_ROOT,
    show_default=True,
    help="Where networkd drop-ins are written. Under /run so a reboot wipes "
    "them and RA emission resumes - the mechanism stays fail-open.",
)
@click.option("--port", default=42, show_default=True)
@click.option("--api-url", default="http://[::1]:42", show_default=True)
@click.option(
    "--peer-url",
    default="",
    help="Base URL of the backup router's wan_healthcheck API. When set, "
    "failover only happens if that peer reports a healthy WAN - there is no "
    "point moving traffic to a router that has no internet either. Empty "
    "disables the gate.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    dry_run: bool,
    interface: str,
    targets_v4: tuple[str, ...],
    targets_v6: tuple[str, ...],
    interval_s: float,
    fall: int,
    rise: int,
    family_fail_pct: float,
    heartbeat_s: float,
    ra_interfaces: tuple[str, ...],
    track_file: Path,
    dropin_root: Path,
    port: int,
    api_url: str,
    peer_url: str,
) -> None:
    """WAN health check and failover. Default command: failover."""
    setup_logging()
    ctx.obj = Settings(
        interface=interface,
        targets_v4=targets_v4,
        targets_v6=targets_v6,
        interval_s=interval_s,
        fall=fall,
        rise=rise,
        family_fail_pct=family_fail_pct,
        heartbeat_s=heartbeat_s,
        ra_interfaces=ra_interfaces,
        track_file=track_file,
        dropin_root=dropin_root,
        port=port,
        api_url=api_url,
        peer_url=peer_url,
        dry_run=dry_run,
    )
    if ctx.invoked_subcommand is None:
        ctx.invoke(failover)


@cli.command()
@click.pass_obj
def failover(settings: Settings) -> None:
    """Fail over: block RAs, send deprecation RAs, drop VRRP priority."""
    sys.exit(asyncio.run(_oneshot(settings, "failover")))


@cli.command()
@click.pass_obj
def fallback(settings: Settings) -> None:
    """Undo a failover: unblock RAs, restore VRRP priority."""
    sys.exit(asyncio.run(_oneshot(settings, "fallback")))


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Print raw JSON.")
@click.pass_obj
def status(settings: Settings, as_json: bool) -> None:
    """Query the running daemon's state."""
    reply = asyncio.run(_api_request(settings, "GET", "/api/v1/status"))
    if reply is None:
        click.echo(f"daemon API unreachable at {settings.api_url}", err=True)
        sys.exit(1)
    if as_json:
        click.echo(json.dumps(reply, indent=2, sort_keys=True))
        return
    verdict = "HEALTHY" if reply.get("healthy") else "DEGRADED"
    if reply.get("forced_failover"):
        verdict += " (FORCED FAILOVER)"
    if reply.get("failover_suppressed"):
        verdict += " (HOLDING - peer unhealthy)"
    click.echo(f"{reply.get('interface') or 'WAN'}: {verdict}")
    if reply.get("peer_checked"):
        click.echo(
            f"  peer: {'healthy' if reply.get('peer_healthy') else 'UNHEALTHY'}"
            f" (reachable={reply.get('peer_reachable')})"
        )
    click.echo(
        f"  failed_over={reply.get('failed_over')} "
        f"ok_streak={reply.get('consecutive_successes')} "
        f"fail_streak={reply.get('consecutive_failures')}"
    )
    click.echo(
        f"  failover state unchanged since {reply.get('state_since_iso')} "
        f"(verdict last moved {reply.get('last_change_iso')})"
    )
    families = dict(reply.get("family_results", {}))
    if families:
        failing = dict(reply.get("family_failing_pct", {}))
        threshold = reply.get("family_fail_pct")
        click.echo(
            "  families: "
            + "  ".join(
                f"{name}={'up' if ok else 'DOWN'}"
                f"({failing.get(name, 0):.0f}%failing)"
                for name, ok in sorted(families.items())
            )
            + f"  [down at >={threshold:g}% failing]"
        )
    for target, ok in sorted(dict(reply.get("probe_results", {})).items()):
        click.echo(f"  {'ok  ' if ok else 'FAIL'} {target}")


@cli.command()
@click.pass_obj
def monitor(settings: Settings) -> None:
    """Run the probing daemon (used by the systemd unit)."""
    sys.exit(asyncio.run(run_monitor(settings)))


if __name__ == "__main__":
    cli()
