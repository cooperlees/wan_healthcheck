"""Command line entry point."""

import asyncio
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any

import click
from aiohttp import web

from .actions import Actions
from .config import DEFAULT_DROPIN_ROOT, Settings
from .keepalived import state_since
from .log import LOG, setup_logging
from .metrics import Metrics
from .monitor import Monitor
from .server import api_request, make_app
from .state import HealthState


async def run_monitor(settings: Settings) -> int:
    state = HealthState()
    # Inherit prior state across daemon restarts (Restart=on-failure must not
    # flap a live failover back and forth).
    try:
        if settings.track_file.read_text().strip() == "1":
            state.healthy = False
            LOG.warning(
                "Starting in DEGRADED state (inherited from %s)",
                settings.track_file,
            )
    except OSError:
        pass
    metrics = Metrics()
    metrics.dry_run.set(1 if settings.dry_run else 0)
    metrics.family_fail_pct_threshold.set(settings.family_fail_pct)
    metrics.start_time.set(time.time())
    metrics.last_state_change.set(state_since(settings.track_file, state.last_change))
    monitor = Monitor(settings, state, metrics, Actions(settings))

    # access_log=None: prometheus scrapes /metrics every 15s, and an access
    # line per scrape is ~5.7k journal lines a day of pure noise.
    runner = web.AppRunner(make_app(monitor), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "::", settings.port)
    await site.start()
    LOG.info(
        "Monitoring %s every %.0fs (fall=%d rise=%d family_fail_pct=%g "
        "targets=%s); API/metrics on [::]:%d%s",
        settings.interface,
        settings.interval_s,
        settings.fall,
        settings.rise,
        settings.family_fail_pct,
        ",".join(settings.targets),
        settings.port,
        " [DRY-RUN]" if settings.dry_run else "",
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        while not stop.is_set():
            started = time.monotonic()
            try:
                await monitor.tick()
            except Exception as exc:  # daemon must survive transient errors
                LOG.error("Monitor tick failed: %s", exc)
            elapsed = time.monotonic() - started
            delay = max(0.0, settings.interval_s - elapsed)
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                pass
    finally:
        await runner.cleanup()
    # Deliberately leave drop-ins + track file untouched on shutdown: stopping
    # the daemon mid-outage must not silently un-fail-over.
    LOG.info("Shutting down (leaving current failover state as-is)")
    return 0


async def _oneshot(settings: Settings, action: str) -> int:
    """failover/fallback: prefer the running daemon's API (so one-shots never
    fight the monitor loop); act directly only when the daemon is down."""
    if settings.dry_run:
        actions = Actions(settings)
        if action == "failover":
            await actions.ensure_failover()
        else:
            await actions.ensure_fallback()
        return 0
    reply = await api_request(settings, "POST", f"/api/v1/{action}")
    if reply is not None:
        LOG.info("Daemon accepted %s: %s", action, json.dumps(reply))
        return 0
    LOG.warning("Daemon API unreachable at %s; acting directly", settings.api_url)
    actions = Actions(settings)
    if action == "failover":
        await actions.ensure_failover()
    else:
        await actions.ensure_fallback()
    return 0


@click.group(invoke_without_command=True)
@click.option("--dry-run", is_flag=True, help="Log actions without executing.")
@click.option(
    "--interface",
    default="",
    show_default=True,
    help="WAN interface to pin probes to with ping -I. Empty means probe "
    "over whatever route the host would normally use, which is what a backup "
    "router wants: 'do I have internet at all', not 'is one link up'.",
)
@click.option(
    "--target-v4",
    "targets_v4",
    multiple=True,
    default=("1.1.1.1", "8.8.8.8"),
    show_default=True,
)
@click.option(
    "--target-v6",
    "targets_v6",
    multiple=True,
    default=("2606:4700:4700::1111", "2001:4860:4860::8888"),
    show_default=True,
)
@click.option("--interval", "interval_s", default=5.0, show_default=True)
@click.option("--fall", default=6, show_default=True)
@click.option("--rise", default=60, show_default=True)
@click.option(
    "--heartbeat-s",
    default=300.0,
    show_default=True,
    help="Seconds between liveness log lines; 0 disables. The daemon is "
    "otherwise silent while healthy, which makes a log view look broken.",
)
@click.option(
    "--family-fail-pct",
    type=click.FloatRange(0, 100, min_open=True),
    default=100.0,
    show_default=True,
    help="Percent of an address family's targets that must fail before that "
    "family counts as down. 100 = every target in the family.",
)
@click.option(
    "--ra-interface",
    "ra_interfaces",
    multiple=True,
    default=(),
    show_default=True,
    help="LAN interface to stop advertising on. Repeatable; required for the\n"
    "IPv6 half of a failover to do anything.",
)
@click.option(
    "--track-file",
    type=click.Path(path_type=Path),
    default=Path("/run/wan_healthcheck/wan_weight"),
    show_default=True,
)
@click.option(
    "--dropin-root",
    type=click.Path(path_type=Path),
    default=DEFAULT_DROPIN_ROOT,
    show_default=True,
    help="Where networkd drop-ins are written. Under /run so a reboot wipes "
    "them and RA emission resumes - the mechanism stays fail-open.",
)
@click.option("--port", default=42, show_default=True)
@click.option("--api-url", default="http://[::1]:42", show_default=True)
@click.option(
    "--peer-url",
    default="",
    help="Base URL of the backup router's wan_healthcheck API. When set, "
    "failover only happens if that peer reports a healthy WAN - there is no "
    "point moving traffic to a router that has no internet either. Empty "
    "disables the gate.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    dry_run: bool,
    interface: str,
    targets_v4: tuple[str, ...],
    targets_v6: tuple[str, ...],
    interval_s: float,
    fall: int,
    rise: int,
    family_fail_pct: float,
    heartbeat_s: float,
    ra_interfaces: tuple[str, ...],
    track_file: Path,
    dropin_root: Path,
    port: int,
    api_url: str,
    peer_url: str,
) -> None:
    """WAN health check and failover. Default command: failover."""
    setup_logging()
    ctx.obj = Settings(
        interface=interface,
        targets_v4=targets_v4,
        targets_v6=targets_v6,
        interval_s=interval_s,
        fall=fall,
        rise=rise,
        family_fail_pct=family_fail_pct,
        heartbeat_s=heartbeat_s,
        ra_interfaces=ra_interfaces,
        track_file=track_file,
        dropin_root=dropin_root,
        port=port,
        api_url=api_url,
        peer_url=peer_url,
        dry_run=dry_run,
    )
    if ctx.invoked_subcommand is None:
        ctx.invoke(failover)


@cli.command()
@click.pass_obj
def failover(settings: Settings) -> None:
    """Fail over: block RAs, send deprecation RAs, drop VRRP priority."""
    sys.exit(asyncio.run(_oneshot(settings, "failover")))


@cli.command()
@click.pass_obj
def fallback(settings: Settings) -> None:
    """Undo a failover: unblock RAs, restore VRRP priority."""
    sys.exit(asyncio.run(_oneshot(settings, "fallback")))


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Print raw JSON.")
@click.pass_obj
def status(settings: Settings, as_json: bool) -> None:
    """Query the running daemon's state."""
    reply = asyncio.run(api_request(settings, "GET", "/api/v1/status"))
    if reply is None:
        click.echo(f"daemon API unreachable at {settings.api_url}", err=True)
        sys.exit(1)
    if as_json:
        click.echo(json.dumps(reply, indent=2, sort_keys=True))
        return
    verdict = "HEALTHY" if reply.get("healthy") else "DEGRADED"
    if reply.get("forced_failover"):
        verdict += " (FORCED FAILOVER)"
    if reply.get("failover_suppressed"):
        verdict += " (HOLDING - peer unhealthy)"
    click.echo(f"{reply.get('interface') or 'WAN'}: {verdict}")
    if reply.get("peer_checked"):
        click.echo(
            f"  peer: {'healthy' if reply.get('peer_healthy') else 'UNHEALTHY'}"
            f" (reachable={reply.get('peer_reachable')})"
        )
    click.echo(
        f"  failed_over={reply.get('failed_over')} "
        f"ok_streak={reply.get('consecutive_successes')} "
        f"fail_streak={reply.get('consecutive_failures')}"
    )
    click.echo(
        f"  failover state unchanged since {reply.get('state_since_iso')} "
        f"(verdict last moved {reply.get('last_change_iso')})"
    )
    families = dict(reply.get("family_results", {}))
    if families:
        failing = dict(reply.get("family_failing_pct", {}))
        threshold = reply.get("family_fail_pct")
        click.echo(
            "  families: "
            + "  ".join(
                f"{name}={'up' if ok else 'DOWN'}"
                f"({failing.get(name, 0):.0f}%failing)"
                for name, ok in sorted(families.items())
            )
            + f"  [down at >={threshold:g}% failing]"
        )
    for target, ok in sorted(dict(reply.get("probe_results", {})).items()):
        click.echo(f"  {'ok  ' if ok else 'FAIL'} {target}")


@cli.command()
@click.pass_obj
def monitor(settings: Settings) -> None:
    """Run the probing daemon (used by the systemd unit)."""
    sys.exit(asyncio.run(run_monitor(settings)))


def entrypoint() -> None:
    """Console-script target; also `python -m wan_healthcheck`."""
    cli()


if __name__ == "__main__":
    entrypoint()
