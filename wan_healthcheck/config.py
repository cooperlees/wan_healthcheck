"""Every tunable, populated from the CLI."""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

DEFAULT_DROPIN_ROOT: Final[Path] = Path("/run/systemd/network")


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
