"""The three switches a failover flips, and their reversal."""

import asyncio
from pathlib import Path

from .config import Settings
from .keepalived import write_track_file
from .log import LOG
from .networkd import (
    DROPIN_BODY,
    NetworkdError,
    apply_networkd,
    dropin_path,
)
from .ra import (
    DEPRECATION_BURSTS,
    DEPRECATION_BURST_GAP_S,
    build_router_advert,
    link_locals_for_interface,
    prefixes_for_interface,
    send_ra_packet,
)


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
            LOG.warning("Wrote 1 to %s (keepalived VRRP priority drops)", s.track_file)

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
            LOG.warning("Resumed RAs on %s", ",".join(s.ra_interfaces))
        if write_track_file(s.track_file, 0):
            LOG.warning(
                "Wrote 0 to %s (keepalived VRRP priority restored)", s.track_file
            )
