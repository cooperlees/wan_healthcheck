"""Unit tests for wan_healthcheck (stdlib unittest; run via
`python3 -m unittest discover -s roles/wan_healthcheck/files/wan_healthcheck`).

No test needs root, real sockets, ping, or a live networkd."""

import asyncio
import logging
import os
import re
import sys
import tempfile
import time
import unittest
from ipaddress import IPv6Address, IPv6Network
from pathlib import Path
from typing import Any
from unittest import mock

from click.testing import CliRunner
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

import wan_healthcheck as whc


def make_settings(**overrides: Any) -> whc.Settings:
    defaults: dict[str, Any] = {
        "interface": "att",
        "targets_v4": ("1.1.1.1", "8.8.8.8"),
        "targets_v6": ("2606:4700:4700::1111", "2001:4860:4860::8888"),
        "interval_s": 5.0,
        "fall": 2,
        "rise": 2,
        "family_fail_pct": 100.0,
        "heartbeat_s": 300.0,
        "ra_interfaces": ("vlan69", "vlan70", "br-k8"),
        "track_file": Path("/nonexistent/att_weight"),
        "dropin_root": Path("/nonexistent/run-systemd-network"),
        "port": 42,
        "api_url": "http://[::1]:42",
        "peer_url": "",
        "dry_run": False,
    }
    defaults.update(overrides)
    return whc.Settings(**defaults)


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
        return whc.GlogFormatter().format(record)

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


class RouterAdvertTest(unittest.TestCase):
    PREFIXES = [
        IPv6Network("2600:1700:1111:2::/64"),
        IPv6Network("2600:1700:1111:4::/64"),
    ]

    def test_bare_ra_dissects(self) -> None:
        packet = whc.build_router_advert([])
        self.assertEqual(len(packet), 16)
        ra = ICMPv6ND_RA(packet)
        self.assertEqual(ra.type, 134)
        self.assertEqual(ra.code, 0)
        self.assertEqual(ra.routerlifetime, 0)
        self.assertEqual(ra.reachabletime, 0)
        self.assertEqual(ra.retranstimer, 0)

    def test_prefix_options(self) -> None:
        packet = whc.build_router_advert(self.PREFIXES)
        self.assertEqual(len(packet), 16 + 32 * len(self.PREFIXES))
        ra = ICMPv6ND_RA(packet)
        seen: list[IPv6Network] = []
        layer = ra.getlayer(ICMPv6NDOptPrefixInfo)
        while layer is not None:
            self.assertEqual(layer.type, 3)
            self.assertEqual(layer.len, 4)
            self.assertEqual(layer.prefixlen, 64)
            self.assertEqual(layer.L, 1)
            self.assertEqual(layer.A, 1)
            self.assertEqual(layer.validlifetime, 7200)
            self.assertEqual(layer.preferredlifetime, 0)
            seen.append(IPv6Network(f"{layer.prefix}/{layer.prefixlen}"))
            layer = layer.payload.getlayer(ICMPv6NDOptPrefixInfo)
        self.assertEqual(seen, self.PREFIXES)

    def test_raw_bytes_sanity(self) -> None:
        packet = whc.build_router_advert(self.PREFIXES)
        self.assertEqual(packet[0], 134)  # ICMPv6 type
        self.assertEqual(packet[1], 0)  # code
        self.assertEqual(packet[2:4], b"\x00\x00")  # checksum left for kernel
        self.assertEqual(packet[6:8], b"\x00\x00")  # router lifetime 0


IF_INET6_FIXTURE = "\n".join(
    [
        # global PD-derived addresses on vlan69 (two in the same /64 -> dedupe)
        "26001700111100020000000000000001 05 40 00 80 vlan69",
        "26001700111100020000000000000069 05 40 00 80 vlan69",
        # a second /64
        "26001700111100040000000000000001 05 40 00 80 vlan69",
        # ULA (kernel scope global, but not is_global) -> excluded
        "fd000001000000000000000000000002 05 40 00 80 vlan69",
        # keepalived VIP /128 link-local -> excluded from RA sources
        "fe800000000000000000000000000001 05 80 20 80 vlan69",
        # static + kernel link-locals -> RA sources
        "fe800000000000000000000000000002 05 40 20 80 vlan69",
        "fe80000000000000ae1f6bfffe6f0d97 05 40 20 80 vlan69",
        # other interface -> ignored
        "26001700111100060000000000000001 06 40 00 80 vlan70",
        "fe800000000000000000000000000002 06 40 20 80 vlan70",
        # loopback (host scope) -> ignored
        "00000000000000000000000000000001 01 80 10 80 lo",
        "",
    ]
)


class ProcNetParsingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.proc = Path(self._dir.name) / "if_inet6"
        self.proc.write_text(IF_INET6_FIXTURE)

    def test_prefixes_for_interface(self) -> None:
        self.assertEqual(
            whc.prefixes_for_interface("vlan69", self.proc),
            [
                IPv6Network("2600:1700:1111:2::/64"),
                IPv6Network("2600:1700:1111:4::/64"),
            ],
        )

    def test_prefixes_other_interface(self) -> None:
        self.assertEqual(
            whc.prefixes_for_interface("vlan70", self.proc),
            [IPv6Network("2600:1700:1111:6::/64")],
        )

    def test_link_locals_exclude_vip(self) -> None:
        self.assertEqual(
            whc.link_locals_for_interface("vlan69", self.proc),
            [
                IPv6Address("fe80::2"),
                IPv6Address("fe80::ae1f:6bff:fe6f:d97"),
            ],
        )

    def test_unknown_interface_empty(self) -> None:
        self.assertEqual(whc.prefixes_for_interface("eth9", self.proc), [])
        self.assertEqual(whc.link_locals_for_interface("eth9", self.proc), [])


class TrackFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "att_weight"

    def test_write_and_idempotency(self) -> None:
        self.assertTrue(whc.write_track_file(self.path, 1))
        self.assertEqual(self.path.read_text(), "1\n")
        self.assertFalse(whc.write_track_file(self.path, 1))
        self.assertTrue(whc.write_track_file(self.path, 0))
        self.assertEqual(self.path.read_text(), "0\n")

    def test_tmpfiles_seed_without_newline_is_not_rewritten(self) -> None:
        # systemd-tmpfiles seeds the file as a bare "0" (1 byte, no newline).
        self.path.write_text("0")
        self.assertFalse(whc.write_track_file(self.path, 0))
        self.assertEqual(self.path.read_text(), "0", "must not rewrite")
        self.assertTrue(whc.write_track_file(self.path, 1))

    def test_atomic_no_tmp_leftover(self) -> None:
        whc.write_track_file(self.path, 1)
        leftovers = [p.name for p in self.path.parent.iterdir()]
        self.assertEqual(leftovers, ["att_weight"])


class StateSinceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "att_weight"

    def test_uses_mtime(self) -> None:
        whc.write_track_file(self.path, 0)
        os.utime(self.path, (1_000_000, 1_000_000))
        self.assertEqual(whc.state_since(self.path, fallback=42.0), 1_000_000)

    def test_missing_file_falls_back(self) -> None:
        self.assertEqual(whc.state_since(self.path, fallback=42.0), 42.0)

    def test_mtime_only_moves_on_real_change(self) -> None:
        whc.write_track_file(self.path, 0)
        os.utime(self.path, (1_000_000, 1_000_000))
        # Re-writing the same value must not touch the file...
        self.assertFalse(whc.write_track_file(self.path, 0))
        self.assertEqual(whc.state_since(self.path, fallback=0.0), 1_000_000)
        # ...but a real transition must.
        self.assertTrue(whc.write_track_file(self.path, 1))
        self.assertGreater(whc.state_since(self.path, fallback=0.0), 1_000_000)

    def test_never_zero_for_dashboard(self) -> None:
        # The 1970 bug: a 0 here renders as ~57 years on a duration panel.
        self.assertNotEqual(whc.state_since(self.path, fallback=time.time()), 0)


class HealthStateTest(unittest.TestCase):
    def test_fall_hysteresis(self) -> None:
        state = whc.HealthState()
        self.assertFalse(state.record_round(False, fall=3, rise=2))
        self.assertFalse(state.record_round(False, fall=3, rise=2))
        self.assertTrue(state.healthy)
        self.assertTrue(state.record_round(False, fall=3, rise=2))
        self.assertFalse(state.healthy)
        self.assertTrue(state.failed_over)

    def test_interleaved_success_resets_fall(self) -> None:
        state = whc.HealthState()
        state.record_round(False, fall=2, rise=2)
        state.record_round(True, fall=2, rise=2)
        self.assertFalse(state.record_round(False, fall=2, rise=2))
        self.assertTrue(state.healthy)

    def test_rise_hysteresis(self) -> None:
        state = whc.HealthState(healthy=False)
        self.assertFalse(state.record_round(True, fall=2, rise=3))
        state.record_round(False, fall=2, rise=3)  # resets the rise streak
        self.assertFalse(state.record_round(True, fall=2, rise=3))
        self.assertFalse(state.record_round(True, fall=2, rise=3))
        self.assertTrue(state.record_round(True, fall=2, rise=3))
        self.assertTrue(state.healthy)

    def test_forced_overrides_healthy_verdict(self) -> None:
        state = whc.HealthState()
        self.assertFalse(state.failed_over)
        state.forced_failover = True
        self.assertTrue(state.failed_over)
        self.assertTrue(state.healthy)

    def test_snapshot_keys(self) -> None:
        snapshot = whc.HealthState().snapshot(100.0)
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


class RoundVerdictTest(unittest.TestCase):
    V4 = ("1.1.1.1", "8.8.8.8")
    V6 = ("2606:4700:4700::1111", "2001:4860:4860::8888")

    def verdict(self, *failing: str, pct: float = 100.0) -> bool:
        results = {t: t not in failing for t in self.V4 + self.V6}
        return whc.round_verdict(results, pct)

    def test_empty_is_unhealthy(self) -> None:
        self.assertFalse(whc.round_verdict({}, 100.0))

    def test_all_up(self) -> None:
        self.assertTrue(self.verdict())

    def test_single_target_down_tolerated(self) -> None:
        for target in self.V4 + self.V6:
            self.assertTrue(self.verdict(target), target)

    def test_one_provider_down_tolerated(self) -> None:
        # Cloudflare (v4 + v6) unreachable, Google still answering both.
        self.assertTrue(self.verdict("1.1.1.1", "2606:4700:4700::1111"))
        self.assertTrue(self.verdict("8.8.8.8", "2001:4860:4860::8888"))

    def test_ipv6_family_down_fails_over(self) -> None:
        # The case a flat majority rule misses: v6 dead, v4 fine.
        self.assertFalse(self.verdict(*self.V6))

    def test_ipv4_family_down_fails_over(self) -> None:
        self.assertFalse(self.verdict(*self.V4))

    def test_everything_down(self) -> None:
        self.assertFalse(self.verdict(*(self.V4 + self.V6)))

    def test_single_family_configured(self) -> None:
        self.assertTrue(
            whc.round_verdict({"1.1.1.1": True, "8.8.8.8": False}, 100.0)
        )
        self.assertFalse(
            whc.round_verdict({"1.1.1.1": False, "8.8.8.8": False}, 100.0)
        )

    def test_default_pct_needs_whole_family(self) -> None:
        # At 100 one surviving target keeps the family up; both dead fails it.
        self.assertTrue(self.verdict("2606:4700:4700::1111", pct=100))
        self.assertFalse(self.verdict(*self.V6, pct=100))

    def test_pct_50_trips_on_half_a_family(self) -> None:
        # Half of a 2-target family is 50%, so one dead target is enough.
        self.assertFalse(self.verdict("2606:4700:4700::1111", pct=50))
        self.assertTrue(self.verdict(pct=50))

    def test_pct_boundary_is_inclusive(self) -> None:
        # failing share == pct counts as down (>=, not >).
        oks = [True, False]  # exactly 50% failing
        self.assertEqual(whc.family_failing_pct(oks), 50.0)
        self.assertFalse(whc.family_results({"1.1.1.1": True, "8.8.8.8": False}, 50)["ipv4"])
        self.assertTrue(whc.family_results({"1.1.1.1": True, "8.8.8.8": False}, 50.1)["ipv4"])

    def test_pct_applies_per_family_not_across_all(self) -> None:
        # Both v4 targets dead is 100% of v4 but only 50% of everything; the
        # family view is what must trip, which a flat rule would miss.
        self.assertFalse(self.verdict(*self.V4, pct=100))

    def test_low_pct_trips_on_a_single_target(self) -> None:
        for target in self.V4 + self.V6:
            self.assertFalse(self.verdict(target, pct=1), target)

    def test_family_failing_pct_values(self) -> None:
        self.assertEqual(whc.family_failing_pct([]), 0.0)
        self.assertEqual(whc.family_failing_pct([True, True]), 0.0)
        self.assertEqual(whc.family_failing_pct([True, False]), 50.0)
        self.assertEqual(whc.family_failing_pct([False, False]), 100.0)
        self.assertAlmostEqual(
            whc.family_failing_pct([False, True, True]), 100 / 3
        )

    def test_thirds_do_not_trip_at_100(self) -> None:
        # Float division must not let 2/3 failing read as 100%.
        results = {"1.1.1.1": False, "8.8.8.8": False, "9.9.9.9": True}
        self.assertTrue(whc.round_verdict(results, 100.0))
        results["9.9.9.9"] = False
        self.assertFalse(whc.round_verdict(results, 100.0))

    def test_unparseable_target_is_its_own_family(self) -> None:
        results = {"1.1.1.1": True, "2606:4700:4700::1111": True, "host": False}
        self.assertFalse(whc.round_verdict(results, 100.0))
        results["host"] = True
        self.assertTrue(whc.round_verdict(results, 100.0))


class MetricsTest(unittest.TestCase):
    def test_observe_state_and_transitions(self) -> None:
        metrics = whc.Metrics()
        state = whc.HealthState()
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
        self.assertIsNotNone(
            get("wan_healthcheck_last_state_change_timestamp_seconds")
        )

    def test_family_healthy_metric(self) -> None:
        metrics = whc.Metrics()
        state = whc.HealthState()
        # v4 still has a live target; v6 is entirely down.
        state.probe_results = {
            "1.1.1.1": True,
            "8.8.8.8": False,
            "2606:4700:4700::1111": False,
            "2001:4860:4860::8888": False,
        }
        metrics.observe_state(state, 100.0)
        get = metrics.registry.get_sample_value
        self.assertEqual(
            get("wan_healthcheck_family_healthy", {"family": "ipv4"}), 1
        )
        self.assertEqual(
            get("wan_healthcheck_family_healthy", {"family": "ipv6"}), 0
        )
        self.assertEqual(
            get("wan_healthcheck_family_failing_pct", {"family": "ipv4"}), 50
        )
        self.assertEqual(
            get("wan_healthcheck_family_failing_pct", {"family": "ipv6"}), 100
        )

    def test_family_healthy_follows_configured_pct(self) -> None:
        metrics = whc.Metrics()
        state = whc.HealthState()
        state.probe_results = {"1.1.1.1": True, "8.8.8.8": False}
        # Same 50%-failing input, opposite verdicts either side of the pct.
        metrics.observe_state(state, 100.0)
        get = metrics.registry.get_sample_value
        self.assertEqual(
            get("wan_healthcheck_family_healthy", {"family": "ipv4"}), 1
        )
        metrics.observe_state(state, 50.0)
        self.assertEqual(
            get("wan_healthcheck_family_healthy", {"family": "ipv4"}), 0
        )

    def test_threshold_metric_exported(self) -> None:
        metrics = whc.Metrics()
        metrics.family_fail_pct_threshold.set(75.0)
        self.assertEqual(
            metrics.registry.get_sample_value(
                "wan_healthcheck_family_fail_pct_threshold"
            ),
            75.0,
        )


class NetworkdHelpersTest(unittest.TestCase):
    JSON = '{"Index":11,"Name":"vlan69","NetworkFile":"/etc/systemd/network/71-vlan69.network"}'

    def test_network_file_from_json(self) -> None:
        with mock.patch.object(whc, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout=self.JSON, stderr="")
            path = whc.network_file_for("vlan69")
        self.assertEqual(path, Path("/etc/systemd/network/71-vlan69.network"))
        self.assertEqual(
            nc.call_args[0], ("--json=short", "status", "vlan69")
        )

    def test_network_file_failure_raises(self) -> None:
        with mock.patch.object(whc, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=1, stdout="", stderr="boom")
            with self.assertRaises(whc.NetworkdError):
                whc.network_file_for("vlan69")

    def test_unmanaged_link_raises(self) -> None:
        with mock.patch.object(whc, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout="{}", stderr="")
            with self.assertRaises(whc.NetworkdError):
                whc.network_file_for("vlan69")

    def test_dropin_path_sits_beside_network_file(self) -> None:
        with mock.patch.object(whc, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout=self.JSON, stderr="")
            path = whc.dropin_path("vlan69", Path("/run/systemd/network"))
        self.assertEqual(
            path,
            Path("/run/systemd/network/71-vlan69.network.d/wan_healthcheck.conf"),
        )

    def test_apply_networkd_reloads_then_reconfigures(self) -> None:
        with mock.patch.object(whc, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            whc.apply_networkd(["vlan69", "br-k8"])
        self.assertEqual(nc.call_args_list[0][0], ("reload",))
        self.assertEqual(
            nc.call_args_list[1][0], ("reconfigure", "vlan69", "br-k8")
        )

    def test_apply_networkd_raises_on_failure(self) -> None:
        with mock.patch.object(whc, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=1, stdout="", stderr="denied")
            with self.assertRaises(whc.NetworkdError):
                whc.apply_networkd(["vlan69"])

    def test_dropin_body_stops_ra(self) -> None:
        self.assertIn("IPv6SendRA=no", whc.DROPIN_BODY)


class ActionsDryRunTest(unittest.IsolatedAsyncioTestCase):
    async def test_dry_run_touches_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            track = Path(tmp) / "att_weight"
            settings = make_settings(dry_run=True, track_file=track)
            actions = whc.Actions(settings)
            with (
                mock.patch.object(whc, "send_ra_packet") as send,
                mock.patch.object(whc, "apply_networkd") as apply_nd,
                mock.patch.object(whc, "dropin_path") as dropin,
            ):
                await actions.ensure_failover()
                await actions.ensure_fallback()
            send.assert_not_called()
            apply_nd.assert_not_called()
            dropin.assert_not_called()
            self.assertFalse(track.exists())

    async def test_dry_run_logs_only_on_intent_change(self) -> None:
        settings = make_settings(dry_run=True)
        actions = whc.Actions(settings)
        with self.assertLogs(whc.LOG, level="INFO") as logs:
            await actions.ensure_fallback()
            await actions.ensure_fallback()
            await actions.ensure_fallback()
            await actions.ensure_failover()
            await actions.ensure_failover()
            await actions.ensure_fallback()
        # One line per transition, not one per tick.
        self.assertEqual(len(logs.records), 3)


class ActionsTest(unittest.IsolatedAsyncioTestCase):
    """Drop-in based RA suppression, with a real temp dropin_root."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        root = Path(self._dir.name)
        self.track = root / "att_weight"
        # Mirror the tmpfiles.d-created, daemon-writable drop-in dirs.
        self.dropins = {}
        for iface, base in (
            ("vlan69", "71-vlan69.network"),
            ("vlan70", "72-vlan70.network"),
            ("br-k8", "74-br-k8.network"),
        ):
            d = root / f"{base}.d"
            d.mkdir()
            self.dropins[iface] = d / whc.DROPIN_NAME
        self.settings = make_settings(track_file=self.track, dropin_root=root)
        self.actions = whc.Actions(self.settings)
        self._patch = mock.patch.object(
            whc,
            "dropin_path",
            side_effect=lambda iface, root: self.dropins[iface],
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    async def test_failover_writes_dropins_and_sends_ras(self) -> None:
        with (
            mock.patch.object(whc, "apply_networkd") as apply_nd,
            mock.patch.object(whc, "send_ra_packet") as send,
            mock.patch.object(whc, "prefixes_for_interface", return_value=[]),
            mock.patch.object(
                whc,
                "link_locals_for_interface",
                return_value=[IPv6Address("fe80::2")],
            ),
            mock.patch.object(whc, "DEPRECATION_BURST_GAP_S", 0.0),
        ):
            await self.actions.ensure_failover()
        for path in self.dropins.values():
            self.assertIn("IPv6SendRA=no", path.read_text())
        apply_nd.assert_called_once_with(("vlan69", "vlan70", "br-k8"))
        # 3 bursts x 3 interfaces x 1 link-local source
        self.assertEqual(send.call_count, 9)
        self.assertEqual(self.track.read_text(), "1\n")

    async def test_failover_already_applied_is_quiet(self) -> None:
        for path in self.dropins.values():
            path.write_text(whc.DROPIN_BODY)
        whc.write_track_file(self.track, 1)
        with (
            mock.patch.object(whc, "apply_networkd") as apply_nd,
            mock.patch.object(whc, "send_ra_packet") as send,
        ):
            await self.actions.ensure_failover()
        # No churn: networkd is not poked and no RAs are re-sent every tick.
        apply_nd.assert_not_called()
        send.assert_not_called()

    async def test_fallback_removes_dropins(self) -> None:
        for path in self.dropins.values():
            path.write_text(whc.DROPIN_BODY)
        with mock.patch.object(whc, "apply_networkd") as apply_nd:
            await self.actions.ensure_fallback()
        for path in self.dropins.values():
            self.assertFalse(path.exists())
        # Removing the file is inert until networkd re-reads it.
        apply_nd.assert_called_once_with(("vlan69", "vlan70", "br-k8"))
        self.assertEqual(self.track.read_text(), "0\n")

    async def test_fallback_nothing_present(self) -> None:
        with mock.patch.object(whc, "apply_networkd") as apply_nd:
            await self.actions.ensure_fallback()
        apply_nd.assert_not_called()
        self.assertEqual(self.track.read_text(), "0\n")

    async def test_failover_rolls_back_dropins_if_networkd_fails(self) -> None:
        # Leaving the files behind would make the next tick see nothing
        # missing and skip the work, so networkd would never read them:
        # IPv4 fails over while IPv6 silently does not.
        with (
            mock.patch.object(
                whc, "apply_networkd", side_effect=whc.NetworkdError("denied")
            ),
            mock.patch.object(whc, "send_ra_packet"),
        ):
            with self.assertRaises(whc.NetworkdError):
                await self.actions.ensure_failover()
        for path in self.dropins.values():
            self.assertFalse(path.exists(), "drop-in must be rolled back")
        # And the failover must not be recorded as done.
        self.assertFalse(self.track.exists())


class PeerGateTest(unittest.IsolatedAsyncioTestCase):
    """Failing over to a backup that has no internet makes an outage worse."""

    def _monitor(self, **overrides: Any) -> whc.Monitor:
        settings = make_settings(fall=2, rise=2, **overrides)
        actions = mock.MagicMock()
        actions.ensure_failover = mock.AsyncMock()
        actions.ensure_fallback = mock.AsyncMock()
        return whc.Monitor(settings, whc.HealthState(), whc.Metrics(), actions)

    @staticmethod
    def _results(ok: bool) -> dict[str, bool]:
        return {t: ok for t in ("1.1.1.1", "8.8.8.8", "2606::1", "2001::8")}

    def test_no_peer_configured_is_transparent(self) -> None:
        state = whc.HealthState(healthy=False)
        self.assertTrue(state.failed_over)
        self.assertFalse(state.failover_suppressed)

    def test_unhealthy_peer_blocks_failover(self) -> None:
        state = whc.HealthState(healthy=False, peer_healthy=False)
        self.assertFalse(state.failed_over)
        self.assertTrue(state.failover_suppressed)

    def test_forced_bypasses_the_gate(self) -> None:
        state = whc.HealthState(
            healthy=False, peer_healthy=False, forced_failover=True
        )
        self.assertTrue(state.failed_over)

    def test_healthy_peer_allows_failover(self) -> None:
        state = whc.HealthState(healthy=False, peer_healthy=True)
        self.assertTrue(state.failed_over)

    async def test_degraded_wan_with_dead_peer_holds_position(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            whc, "_api_request", new=mock.AsyncMock(return_value={"healthy": False})
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
            whc, "_api_request", new=mock.AsyncMock(return_value={"healthy": True})
        ):
            await monitor.tick(self._results(False))
            await monitor.tick(self._results(False))
        monitor.actions.ensure_failover.assert_awaited()
        self.assertEqual(
            monitor.metrics.registry.get_sample_value(
                "wan_healthcheck_failed_over"
            ),
            1,
        )

    async def test_peer_unreachable_tolerated_then_marked_down(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            whc, "_api_request", new=mock.AsyncMock(return_value=None)
        ):
            await monitor.tick(self._results(True))
            # One blip must not disqualify the peer (fall=2 here).
            self.assertTrue(monitor.state.peer_healthy)
            self.assertFalse(monitor.state.peer_reachable)
            await monitor.tick(self._results(True))
        self.assertFalse(monitor.state.peer_healthy)
        self.assertEqual(
            monitor.metrics.registry.get_sample_value(
                "wan_healthcheck_peer_reachable"
            ),
            0,
        )

    async def test_peer_that_has_itself_failed_over_is_still_viable(self) -> None:
        # A peer reporting failed_over moved traffic somewhere; that does not
        # mean it lacks internet.
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        with mock.patch.object(
            whc,
            "_api_request",
            new=mock.AsyncMock(return_value={"healthy": True, "failed_over": True}),
        ):
            await monitor.tick(self._results(False))
            await monitor.tick(self._results(False))
        monitor.actions.ensure_failover.assert_awaited()

    async def test_peer_polled_at_its_own_url(self) -> None:
        monitor = self._monitor(peer_url="http://[fd00:1::3]:42")
        api = mock.AsyncMock(return_value={"healthy": True})
        with mock.patch.object(whc, "_api_request", new=api):
            await monitor.tick(self._results(True))
        self.assertEqual(
            api.await_args[0][1:], ("GET", "/api/v1/status")
        )
        self.assertEqual(api.await_args[1]["base"], "http://[fd00:1::3]:42")


class MonitorTickTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.settings = make_settings(fall=2, rise=2)
        self.state = whc.HealthState()
        self.metrics = whc.Metrics()
        self.actions = mock.MagicMock()
        self.actions.ensure_failover = mock.AsyncMock()
        self.actions.ensure_fallback = mock.AsyncMock()
        self.monitor = whc.Monitor(
            self.settings, self.state, self.metrics, self.actions
        )

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
        self.assertEqual(
            get("wan_healthcheck_rounds_total", {"result": "healthy"}), 2
        )

    async def test_heartbeat_is_rate_limited(self) -> None:
        with self.assertLogs(whc.LOG, level="INFO") as logs:
            for _ in range(5):
                await self.monitor.tick(self._results(True))
        beats = [r for r in logs.records if "heartbeat:" in r.getMessage()]
        self.assertEqual(len(beats), 1, "one beat, not one per tick")
        self.assertIn("att HEALTHY (armed)", beats[0].getMessage())
        self.assertIn("ipv4=0%failing", beats[0].getMessage())

    async def test_heartbeat_repeats_after_interval(self) -> None:
        self.monitor.settings = make_settings(heartbeat_s=0.001)
        with self.assertLogs(whc.LOG, level="INFO") as logs:
            await self.monitor.tick(self._results(True))
            await asyncio.sleep(0.002)
            await self.monitor.tick(self._results(True))
        beats = [r for r in logs.records if "heartbeat:" in r.getMessage()]
        self.assertEqual(len(beats), 2)

    async def test_heartbeat_disabled_by_zero(self) -> None:
        self.monitor.settings = make_settings(heartbeat_s=0)
        with self.assertLogs(whc.LOG, level="INFO") as logs:
            await self.monitor.tick(self._results(True))
            LOG_MARKER = "marker so assertLogs has a record"
            whc.LOG.info(LOG_MARKER)
        self.assertEqual(
            [r for r in logs.records if "heartbeat:" in r.getMessage()], []
        )

    async def test_heartbeat_reports_degraded_and_dry_run(self) -> None:
        self.monitor.settings = make_settings(dry_run=True, fall=1)
        with self.assertLogs(whc.LOG, level="INFO") as logs:
            await self.monitor.tick(self._results(False))
        beat = next(r for r in logs.records if "heartbeat:" in r.getMessage())
        self.assertIn("att DEGRADED (report-only)", beat.getMessage())
        self.assertIn("ipv4=100%failing", beat.getMessage())

    async def test_forced_state_wins_over_healthy_probes(self) -> None:
        self.state.forced_failover = True
        await self.monitor.tick(self._results(True))
        self.actions.ensure_failover.assert_awaited()
        self.actions.ensure_fallback.assert_not_awaited()


class ApiRoutesTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from aiohttp.test_utils import TestClient, TestServer

        self.settings = make_settings()
        self.state = whc.HealthState()
        self.metrics = whc.Metrics()
        self.actions = mock.MagicMock()
        self.actions.ensure_failover = mock.AsyncMock()
        self.actions.ensure_fallback = mock.AsyncMock()
        monitor = whc.Monitor(
            self.settings, self.state, self.metrics, self.actions
        )
        self.client = TestClient(TestServer(whc.make_app(monitor)))
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        await self.client.close()

    async def test_metrics_route(self) -> None:
        response = await self.client.get("/metrics")
        self.assertEqual(response.status, 200)
        self.assertTrue(
            response.headers["Content-Type"].startswith("text/plain")
        )
        body = await response.text()
        self.assertIn("wan_healthcheck_healthy", body)
        self.assertIn("wan_healthcheck_rounds_total", body)

    async def test_status_route(self) -> None:
        response = await self.client.get("/api/v1/status")
        self.assertEqual(response.status, 200)
        body = await response.json()
        self.assertTrue(body["healthy"])
        self.assertFalse(body["failed_over"])
        self.assertEqual(body["interface"], "att")
        self.assertFalse(body["dry_run"])

    async def test_forced_failover_roundtrip(self) -> None:
        response = await self.client.post("/api/v1/failover")
        body = await response.json()
        self.assertTrue(body["forced_failover"])
        self.assertTrue(body["failed_over"])
        self.actions.ensure_failover.assert_awaited()
        self.assertEqual(
            self.metrics.registry.get_sample_value(
                "wan_healthcheck_failovers_total"
            ),
            1,
        )
        response = await self.client.post("/api/v1/fallback")
        body = await response.json()
        self.assertFalse(body["forced_failover"])
        self.assertFalse(body["failed_over"])
        self.actions.ensure_fallback.assert_awaited()


class OneshotApiFirstTest(unittest.IsolatedAsyncioTestCase):
    async def test_api_reachable_no_direct_action(self) -> None:
        settings = make_settings()
        with (
            mock.patch.object(
                whc,
                "_api_request",
                new=mock.AsyncMock(return_value={"failed_over": True}),
            ) as api,
            mock.patch.object(whc, "Actions") as actions_cls,
        ):
            rc = await whc._oneshot(settings, "failover")
        self.assertEqual(rc, 0)
        api.assert_awaited_once_with(settings, "POST", "/api/v1/failover")
        actions_cls.assert_not_called()

    async def test_api_unreachable_acts_directly(self) -> None:
        settings = make_settings()
        fake_actions = mock.MagicMock()
        fake_actions.ensure_fallback = mock.AsyncMock()
        with (
            mock.patch.object(
                whc, "_api_request", new=mock.AsyncMock(return_value=None)
            ),
            mock.patch.object(
                whc, "Actions", return_value=fake_actions
            ) as actions_cls,
        ):
            rc = await whc._oneshot(settings, "fallback")
        self.assertEqual(rc, 0)
        actions_cls.assert_called_once()
        fake_actions.ensure_fallback.assert_awaited_once()


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_default_command_is_failover(self) -> None:
        with mock.patch.object(
            whc, "_oneshot", new=mock.AsyncMock(return_value=0)
        ) as oneshot:
            result = self.runner.invoke(whc.cli, [])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(oneshot.await_args[0][1], "failover")

    def test_fallback_command(self) -> None:
        with mock.patch.object(
            whc, "_oneshot", new=mock.AsyncMock(return_value=0)
        ) as oneshot:
            result = self.runner.invoke(whc.cli, ["fallback"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(oneshot.await_args[0][1], "fallback")

    def test_dry_run_flag_reaches_settings(self) -> None:
        with mock.patch.object(
            whc, "_oneshot", new=mock.AsyncMock(return_value=0)
        ) as oneshot:
            result = self.runner.invoke(whc.cli, ["--dry-run", "failover"])
        self.assertEqual(result.exit_code, 0)
        settings = oneshot.await_args[0][0]
        self.assertTrue(settings.dry_run)

    def test_dry_run_oneshot_executes_nothing(self) -> None:
        with (
            mock.patch.object(whc, "send_ra_packet") as send,
            mock.patch.object(whc, "apply_networkd") as apply_nd,
        ):
            result = self.runner.invoke(whc.cli, ["--dry-run", "failover"])
        self.assertEqual(result.exit_code, 0)
        send.assert_not_called()
        apply_nd.assert_not_called()

    def test_status_daemon_down_exits_nonzero(self) -> None:
        with mock.patch.object(
            whc, "_api_request", new=mock.AsyncMock(return_value=None)
        ):
            result = self.runner.invoke(whc.cli, ["status"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unreachable", result.output)

    def test_status_renders_state(self) -> None:
        reply = {
            "healthy": True,
            "forced_failover": False,
            "failed_over": False,
            "consecutive_successes": 12,
            "consecutive_failures": 0,
            "last_change_iso": "2026-08-12T00:00:00",
            "probe_results": {"1.1.1.1": True, "2606:4700:4700::1111": False},
            "interface": "att",
        }
        with mock.patch.object(
            whc, "_api_request", new=mock.AsyncMock(return_value=reply)
        ):
            result = self.runner.invoke(whc.cli, ["status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("att: HEALTHY", result.output)
        self.assertIn("FAIL 2606:4700:4700::1111", result.output)

    def test_status_json(self) -> None:
        reply = {"healthy": False, "failed_over": True}
        with mock.patch.object(
            whc, "_api_request", new=mock.AsyncMock(return_value=reply)
        ):
            result = self.runner.invoke(whc.cli, ["status", "--json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"failed_over": true', result.output)


class ProbeVerdictIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_probe_round_maps_targets(self) -> None:
        settings = make_settings()

        async def fake_probe(interface: str, target: str) -> bool:
            return target.endswith("1.1.1.1") or target.startswith("2606")

        with mock.patch.object(whc, "probe_target", new=fake_probe):
            results = await whc.probe_round(settings)
        self.assertEqual(
            results,
            {
                "1.1.1.1": True,
                "8.8.8.8": False,
                "2606:4700:4700::1111": True,
                "2001:4860:4860::8888": False,
            },
        )
        self.assertTrue(whc.round_verdict(results, 100.0))


if __name__ == "__main__":
    unittest.main()
