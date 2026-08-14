import tempfile
import unittest
from ipaddress import IPv6Address
from pathlib import Path
from unittest import mock
from wan_healthcheck import actions as actions_mod
from wan_healthcheck.actions import Actions
from wan_healthcheck.keepalived import write_track_file
from wan_healthcheck.networkd import DROPIN_BODY, DROPIN_NAME, NetworkdError
from .helpers import make_settings


class ActionsDryRunTest(unittest.IsolatedAsyncioTestCase):
    async def test_dry_run_touches_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            track = Path(tmp) / "att_weight"
            settings = make_settings(dry_run=True, track_file=track)
            actions = Actions(settings)
            with (
                mock.patch.object(actions_mod, "send_ra_packet") as send,
                mock.patch.object(actions_mod, "apply_networkd") as apply_nd,
                mock.patch.object(actions_mod, "dropin_path") as dropin,
            ):
                await actions.ensure_failover()
                await actions.ensure_fallback()
            send.assert_not_called()
            apply_nd.assert_not_called()
            dropin.assert_not_called()
            self.assertFalse(track.exists())

    async def test_dry_run_logs_only_on_intent_change(self) -> None:
        settings = make_settings(dry_run=True)
        actions = Actions(settings)
        with self.assertLogs(actions_mod.LOG, level="INFO") as logs:
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
            self.dropins[iface] = d / DROPIN_NAME
        self.settings = make_settings(track_file=self.track, dropin_root=root)
        self.actions = Actions(self.settings)
        self._patch = mock.patch.object(
            actions_mod,
            "dropin_path",
            side_effect=lambda iface, root: self.dropins[iface],
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    async def test_failover_writes_dropins_and_sends_ras(self) -> None:
        with (
            mock.patch.object(actions_mod, "apply_networkd") as apply_nd,
            mock.patch.object(actions_mod, "send_ra_packet") as send,
            mock.patch.object(actions_mod, "prefixes_for_interface", return_value=[]),
            mock.patch.object(
                actions_mod,
                "link_locals_for_interface",
                return_value=[IPv6Address("fe80::2")],
            ),
            mock.patch.object(actions_mod, "DEPRECATION_BURST_GAP_S", 0.0),
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
            path.write_text(DROPIN_BODY)
        write_track_file(self.track, 1)
        with (
            mock.patch.object(actions_mod, "apply_networkd") as apply_nd,
            mock.patch.object(actions_mod, "send_ra_packet") as send,
        ):
            await self.actions.ensure_failover()
        # No churn: networkd is not poked and no RAs are re-sent every tick.
        apply_nd.assert_not_called()
        send.assert_not_called()

    async def test_fallback_removes_dropins(self) -> None:
        for path in self.dropins.values():
            path.write_text(DROPIN_BODY)
        with mock.patch.object(actions_mod, "apply_networkd") as apply_nd:
            await self.actions.ensure_fallback()
        for path in self.dropins.values():
            self.assertFalse(path.exists())
        # Removing the file is inert until networkd re-reads it.
        apply_nd.assert_called_once_with(("vlan69", "vlan70", "br-k8"))
        self.assertEqual(self.track.read_text(), "0\n")

    async def test_fallback_nothing_present(self) -> None:
        with mock.patch.object(actions_mod, "apply_networkd") as apply_nd:
            await self.actions.ensure_fallback()
        apply_nd.assert_not_called()
        self.assertEqual(self.track.read_text(), "0\n")

    async def test_failover_rolls_back_dropins_if_networkd_fails(self) -> None:
        # Leaving the files behind would make the next tick see nothing
        # missing and skip the work, so networkd would never read them:
        # IPv4 fails over while IPv6 silently does not.
        with (
            mock.patch.object(
                actions_mod, "apply_networkd", side_effect=NetworkdError("denied")
            ),
            mock.patch.object(actions_mod, "send_ra_packet"),
        ):
            with self.assertRaises(NetworkdError):
                await self.actions.ensure_failover()
        for path in self.dropins.values():
            self.assertFalse(path.exists(), "drop-in must be rolled back")
        # And the failover must not be recorded as done.
        self.assertFalse(self.track.exists())
