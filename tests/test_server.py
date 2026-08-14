import unittest
from unittest import mock
from wan_healthcheck.metrics import Metrics
from wan_healthcheck.monitor import Monitor
from wan_healthcheck.server import make_app
from wan_healthcheck.state import HealthState
from .helpers import make_settings


class ApiRoutesTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from aiohttp.test_utils import TestClient, TestServer

        self.settings = make_settings()
        self.state = HealthState()
        self.metrics = Metrics()
        self.actions = mock.MagicMock()
        self.actions.ensure_failover = mock.AsyncMock()
        self.actions.ensure_fallback = mock.AsyncMock()
        monitor = Monitor(self.settings, self.state, self.metrics, self.actions)
        self.client = TestClient(TestServer(make_app(monitor)))
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        await self.client.close()

    async def test_metrics_route(self) -> None:
        response = await self.client.get("/metrics")
        self.assertEqual(response.status, 200)
        self.assertTrue(response.headers["Content-Type"].startswith("text/plain"))
        body = await response.text()
        self.assertIn("wan_healthcheck_healthy", body)
        self.assertIn("wan_healthcheck_rounds_total", body)

    async def test_status_route(self) -> None:
        response = await self.client.get("/api/v1/status")
        self.assertEqual(response.status, 200)
        body = await response.json()
        self.assertTrue(body["healthy"])
        self.assertFalse(body["failed_over"])
        self.assertEqual(body["interface"], "att")
        self.assertFalse(body["dry_run"])

    async def test_forced_failover_roundtrip(self) -> None:
        response = await self.client.post("/api/v1/failover")
        body = await response.json()
        self.assertTrue(body["forced_failover"])
        self.assertTrue(body["failed_over"])
        self.actions.ensure_failover.assert_awaited()
        self.assertEqual(
            self.metrics.registry.get_sample_value("wan_healthcheck_failovers_total"),
            1,
        )
        response = await self.client.post("/api/v1/fallback")
        body = await response.json()
        self.assertFalse(body["forced_failover"])
        self.assertFalse(body["failed_over"])
        self.actions.ensure_fallback.assert_awaited()
