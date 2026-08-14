import unittest
from unittest import mock
from click.testing import CliRunner
from wan_healthcheck import actions as actions_mod
from wan_healthcheck import main as main_mod
from wan_healthcheck.main import cli
from .helpers import make_settings


class OneshotApiFirstTest(unittest.IsolatedAsyncioTestCase):
    async def test_api_reachable_no_direct_action(self) -> None:
        settings = make_settings()
        with (
            mock.patch.object(
                main_mod,
                "api_request",
                new=mock.AsyncMock(return_value={"failed_over": True}),
            ) as api,
            mock.patch.object(main_mod, "Actions") as actions_cls,
        ):
            rc = await main_mod._oneshot(settings, "failover")
        self.assertEqual(rc, 0)
        api.assert_awaited_once_with(settings, "POST", "/api/v1/failover")
        actions_cls.assert_not_called()

    async def test_api_unreachable_acts_directly(self) -> None:
        settings = make_settings()
        fake_actions = mock.MagicMock()
        fake_actions.ensure_fallback = mock.AsyncMock()
        with (
            mock.patch.object(
                main_mod, "api_request", new=mock.AsyncMock(return_value=None)
            ),
            mock.patch.object(
                main_mod, "Actions", return_value=fake_actions
            ) as actions_cls,
        ):
            rc = await main_mod._oneshot(settings, "fallback")
        self.assertEqual(rc, 0)
        actions_cls.assert_called_once()
        fake_actions.ensure_fallback.assert_awaited_once()


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_default_command_is_failover(self) -> None:
        with mock.patch.object(
            main_mod, "_oneshot", new=mock.AsyncMock(return_value=0)
        ) as oneshot:
            result = self.runner.invoke(cli, [])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(oneshot.await_args[0][1], "failover")

    def test_fallback_command(self) -> None:
        with mock.patch.object(
            main_mod, "_oneshot", new=mock.AsyncMock(return_value=0)
        ) as oneshot:
            result = self.runner.invoke(cli, ["fallback"])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(oneshot.await_args[0][1], "fallback")

    def test_dry_run_flag_reaches_settings(self) -> None:
        with mock.patch.object(
            main_mod, "_oneshot", new=mock.AsyncMock(return_value=0)
        ) as oneshot:
            result = self.runner.invoke(cli, ["--dry-run", "failover"])
        self.assertEqual(result.exit_code, 0)
        settings = oneshot.await_args[0][0]
        self.assertTrue(settings.dry_run)

    def test_dry_run_oneshot_executes_nothing(self) -> None:
        with (
            mock.patch.object(actions_mod, "send_ra_packet") as send,
            mock.patch.object(actions_mod, "apply_networkd") as apply_nd,
        ):
            result = self.runner.invoke(cli, ["--dry-run", "failover"])
        self.assertEqual(result.exit_code, 0)
        send.assert_not_called()
        apply_nd.assert_not_called()

    def test_status_daemon_down_exits_nonzero(self) -> None:
        with mock.patch.object(
            main_mod, "api_request", new=mock.AsyncMock(return_value=None)
        ):
            result = self.runner.invoke(cli, ["status"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("unreachable", result.output)

    def test_status_renders_state(self) -> None:
        reply = {
            "healthy": True,
            "forced_failover": False,
            "failed_over": False,
            "consecutive_successes": 12,
            "consecutive_failures": 0,
            "last_change_iso": "2026-08-12T00:00:00",
            "probe_results": {"1.1.1.1": True, "2606:4700:4700::1111": False},
            "interface": "att",
        }
        with mock.patch.object(
            main_mod, "api_request", new=mock.AsyncMock(return_value=reply)
        ):
            result = self.runner.invoke(cli, ["status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("att: HEALTHY", result.output)
        self.assertIn("FAIL 2606:4700:4700::1111", result.output)

    def test_status_json(self) -> None:
        reply = {"healthy": False, "failed_over": True}
        with mock.patch.object(
            main_mod, "api_request", new=mock.AsyncMock(return_value=reply)
        ):
            result = self.runner.invoke(cli, ["status", "--json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn('"failed_over": true', result.output)
