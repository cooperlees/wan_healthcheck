"""Probing the WAN, and turning a round of results into a verdict."""

import asyncio
from collections.abc import Sequence
from ipaddress import ip_address

from .config import Settings
from .log import LOG


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


def family_results(results: dict[str, bool], fail_pct: float) -> dict[str, bool]:
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
