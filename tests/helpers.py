"""Shared test helpers."""

from pathlib import Path
from typing import Any

from wan_healthcheck.config import Settings


def make_settings(**overrides: Any) -> Settings:
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
    return Settings(**defaults)


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
