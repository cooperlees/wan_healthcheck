import tempfile
import unittest
from ipaddress import IPv6Address, IPv6Network
from pathlib import Path
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo
from wan_healthcheck import ra
from wan_healthcheck.ra import (
    build_router_advert,
    link_locals_for_interface,
    prefixes_for_interface,
)
from .helpers import IF_INET6_FIXTURE


class RouterAdvertTest(unittest.TestCase):
    PREFIXES = [
        IPv6Network("2600:1700:1111:2::/64"),
        IPv6Network("2600:1700:1111:4::/64"),
    ]

    def test_bare_ra_dissects(self) -> None:
        packet = build_router_advert([])
        self.assertEqual(len(packet), 16)
        ra = ICMPv6ND_RA(packet)
        self.assertEqual(ra.type, 134)
        self.assertEqual(ra.code, 0)
        self.assertEqual(ra.routerlifetime, 0)
        self.assertEqual(ra.reachabletime, 0)
        self.assertEqual(ra.retranstimer, 0)

    def test_prefix_options(self) -> None:
        packet = build_router_advert(self.PREFIXES)
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
        packet = build_router_advert(self.PREFIXES)
        self.assertEqual(packet[0], 134)  # ICMPv6 type
        self.assertEqual(packet[1], 0)  # code
        self.assertEqual(packet[2:4], b"\x00\x00")  # checksum left for kernel
        self.assertEqual(packet[6:8], b"\x00\x00")  # router lifetime 0


class ProcNetParsingTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.proc = Path(self._dir.name) / "if_inet6"
        self.proc.write_text(IF_INET6_FIXTURE)

    def test_prefixes_for_interface(self) -> None:
        self.assertEqual(
            prefixes_for_interface("vlan69", self.proc),
            [
                IPv6Network("2600:1700:1111:2::/64"),
                IPv6Network("2600:1700:1111:4::/64"),
            ],
        )

    def test_prefixes_other_interface(self) -> None:
        self.assertEqual(
            prefixes_for_interface("vlan70", self.proc),
            [IPv6Network("2600:1700:1111:6::/64")],
        )

    def test_link_locals_exclude_vip(self) -> None:
        self.assertEqual(
            link_locals_for_interface("vlan69", self.proc),
            [
                IPv6Address("fe80::2"),
                IPv6Address("fe80::ae1f:6bff:fe6f:d97"),
            ],
        )

    def test_unknown_interface_empty(self) -> None:
        self.assertEqual(prefixes_for_interface("eth9", self.proc), [])
        self.assertEqual(link_locals_for_interface("eth9", self.proc), [])
