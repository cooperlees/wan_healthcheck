"""Router Advertisements: reading what a link advertises, and sending the
deprecation RAs that move clients off a dead prefix."""

import socket
from collections.abc import Sequence
from ipaddress import IPv6Address, IPv6Network
from pathlib import Path
from typing import Final

from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

PROC_IF_INET6: Final[Path] = Path("/proc/net/if_inet6")


ALL_NODES_MULTICAST: Final[str] = "ff02::1"


# RFC 4862 clients clamp a received valid lifetime < 2h up to 2h anyway,
# so 7200 is the effective floor; preferred=0 is what actually deprecates.
DEPRECATION_VALID_LIFETIME: Final[int] = 7200


DEPRECATION_BURSTS: Final[int] = 3


DEPRECATION_BURST_GAP_S: Final[float] = 1.0


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


def send_ra_packet(packet: bytes, interface: str, source: IPv6Address) -> None:
    """Transmit a raw ICMPv6 RA to all-nodes on `interface`."""
    ifindex = socket.if_nametoindex(interface)
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.bind((str(source), 0, 0, ifindex))
        sock.sendto(packet, (ALL_NODES_MULTICAST, 0, 0, ifindex))
