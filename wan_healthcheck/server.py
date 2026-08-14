"""The HTTP surface: Prometheus metrics, a status document, and forcing
failover either way. Also the client half, used to poll a peer."""

from typing import TYPE_CHECKING, Any

from aiohttp import ClientError, ClientSession, ClientTimeout, web
from mypy_extensions import mypyc_attr
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .config import Settings
from .log import LOG

if TYPE_CHECKING:  # avoids a cycle: monitor imports api_request from here
    from .monitor import Monitor


@mypyc_attr(native_class=False)
class ApiError(RuntimeError):
    pass


def make_app(monitor: "Monitor") -> web.Application:
    async def metrics_handler(request: web.Request) -> web.Response:
        return web.Response(
            body=generate_latest(monitor.metrics.registry),
            headers={"Content-Type": CONTENT_TYPE_LATEST},
        )

    def status_body() -> dict[str, Any]:
        body = monitor.state.snapshot(monitor.settings.family_fail_pct)
        body["dry_run"] = monitor.settings.dry_run
        body["interface"] = monitor.settings.interface
        return body

    async def status_handler(request: web.Request) -> web.Response:
        return web.json_response(status_body())

    async def failover_handler(request: web.Request) -> web.Response:
        was = monitor.state.failed_over
        monitor.state.forced_failover = True
        if monitor.state.failed_over != was:
            monitor.metrics.observe_effective_change(True)
        LOG.warning("Forced failover requested via API")
        await monitor.actions.ensure_failover()
        monitor.metrics.observe_state(monitor.state, monitor.settings.family_fail_pct)
        return web.json_response(status_body())

    async def fallback_handler(request: web.Request) -> web.Response:
        was = monitor.state.failed_over
        monitor.state.forced_failover = False
        if monitor.state.failed_over != was:
            monitor.metrics.observe_effective_change(False)
        LOG.warning(
            "Forced failover cleared via API (probe verdict: %s)",
            "healthy" if monitor.state.healthy else "degraded",
        )
        if not monitor.state.failed_over:
            await monitor.actions.ensure_fallback()
        monitor.metrics.observe_state(monitor.state, monitor.settings.family_fail_pct)
        return web.json_response(status_body())

    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/api/v1/status", status_handler)
    app.router.add_post("/api/v1/failover", failover_handler)
    app.router.add_post("/api/v1/fallback", fallback_handler)
    return app


async def api_request(
    settings: Settings, method: str, path: str, base: str | None = None
) -> dict[str, Any] | None:
    """Returns the JSON reply, or None if unreachable.

    `base` targets a different daemon (the peer); it defaults to our own API.
    """
    root = base if base is not None else settings.api_url
    try:
        async with ClientSession(timeout=ClientTimeout(total=3)) as session:
            async with session.request(method, f"{root}{path}") as response:
                if response.status != 200:
                    raise ApiError(
                        f"daemon API returned HTTP {response.status} for {path}"
                    )
                body: dict[str, Any] = await response.json()
                return body
    except (ClientError, OSError):
        return None
