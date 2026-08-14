"""Driving systemd-networkd: stopping and resuming RA emission via drop-ins.

Deliberately not a firewall rule. Dropping RAs in nftables' OUTPUT hook
returns EPERM to networkd, and sd-radv responds by stopping its RA timer
permanently and silently - it never resumes when the block lifts. Letting
networkd stop on purpose avoids that and yields its graceful RFC 4861
lifetime-0 shutdown advert for free.
"""

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from mypy_extensions import mypyc_attr


@mypyc_attr(native_class=False)
class NetworkdError(RuntimeError):
    pass


DROPIN_NAME: Final[str] = "wan_healthcheck.conf"


# Stopping RA this way makes networkd emit its own graceful RFC 4861
# shutdown advert (router lifetime 0) and then fall silent, which is what
# lets our deprecation RA stick - see send_deprecation_ras().
DROPIN_BODY: Final[str] = "# Written by wan_healthcheck\n[Network]\nIPv6SendRA=no\n"


def _networkctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["networkctl", *args], capture_output=True, text=True)


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
        raise NetworkdError(f"networkctl reload failed: {reload_result.stderr.strip()}")
    result = _networkctl("reconfigure", *interfaces)
    if result.returncode != 0:
        raise NetworkdError(f"networkctl reconfigure failed: {result.stderr.strip()}")
