import unittest
from pathlib import Path
from unittest import mock
from wan_healthcheck import networkd
from wan_healthcheck.networkd import (
    DROPIN_BODY,
    NetworkdError,
    apply_networkd,
    dropin_path,
    network_file_for,
)


class NetworkdHelpersTest(unittest.TestCase):
    JSON = '{"Index":11,"Name":"vlan69","NetworkFile":"/etc/systemd/network/71-vlan69.network"}'

    def test_network_file_from_json(self) -> None:
        with mock.patch.object(networkd, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout=self.JSON, stderr="")
            path = network_file_for("vlan69")
        self.assertEqual(path, Path("/etc/systemd/network/71-vlan69.network"))
        self.assertEqual(nc.call_args[0], ("--json=short", "status", "vlan69"))

    def test_network_file_failure_raises(self) -> None:
        with mock.patch.object(networkd, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=1, stdout="", stderr="boom")
            with self.assertRaises(NetworkdError):
                network_file_for("vlan69")

    def test_unmanaged_link_raises(self) -> None:
        with mock.patch.object(networkd, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout="{}", stderr="")
            with self.assertRaises(NetworkdError):
                network_file_for("vlan69")

    def test_dropin_path_sits_beside_network_file(self) -> None:
        with mock.patch.object(networkd, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout=self.JSON, stderr="")
            path = dropin_path("vlan69", Path("/run/systemd/network"))
        self.assertEqual(
            path,
            Path("/run/systemd/network/71-vlan69.network.d/wan_healthcheck.conf"),
        )

    def test_apply_networkd_reloads_then_reconfigures(self) -> None:
        with mock.patch.object(networkd, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            apply_networkd(["vlan69", "br-k8"])
        self.assertEqual(nc.call_args_list[0][0], ("reload",))
        self.assertEqual(nc.call_args_list[1][0], ("reconfigure", "vlan69", "br-k8"))

    def test_apply_networkd_raises_on_failure(self) -> None:
        with mock.patch.object(networkd, "_networkctl") as nc:
            nc.return_value = mock.Mock(returncode=1, stdout="", stderr="denied")
            with self.assertRaises(NetworkdError):
                apply_networkd(["vlan69"])

    def test_dropin_body_stops_ra(self) -> None:
        self.assertIn("IPv6SendRA=no", DROPIN_BODY)
