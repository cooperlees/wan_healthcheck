import unittest
from unittest import mock
from wan_healthcheck import probe
from wan_healthcheck.probe import (
    family_failing_pct,
    family_results,
    probe_round,
    round_verdict,
)
from .helpers import make_settings


class RoundVerdictTest(unittest.TestCase):
    V4 = ("1.1.1.1", "8.8.8.8")
    V6 = ("2606:4700:4700::1111", "2001:4860:4860::8888")

    def verdict(self, *failing: str, pct: float = 100.0) -> bool:
        results = {t: t not in failing for t in self.V4 + self.V6}
        return round_verdict(results, pct)

    def test_empty_is_unhealthy(self) -> None:
        self.assertFalse(round_verdict({}, 100.0))

    def test_all_up(self) -> None:
        self.assertTrue(self.verdict())

    def test_single_target_down_tolerated(self) -> None:
        for target in self.V4 + self.V6:
            self.assertTrue(self.verdict(target), target)

    def test_one_provider_down_tolerated(self) -> None:
        # Cloudflare (v4 + v6) unreachable, Google still answering both.
        self.assertTrue(self.verdict("1.1.1.1", "2606:4700:4700::1111"))
        self.assertTrue(self.verdict("8.8.8.8", "2001:4860:4860::8888"))

    def test_ipv6_family_down_fails_over(self) -> None:
        # The case a flat majority rule misses: v6 dead, v4 fine.
        self.assertFalse(self.verdict(*self.V6))

    def test_ipv4_family_down_fails_over(self) -> None:
        self.assertFalse(self.verdict(*self.V4))

    def test_everything_down(self) -> None:
        self.assertFalse(self.verdict(*(self.V4 + self.V6)))

    def test_single_family_configured(self) -> None:
        self.assertTrue(round_verdict({"1.1.1.1": True, "8.8.8.8": False}, 100.0))
        self.assertFalse(round_verdict({"1.1.1.1": False, "8.8.8.8": False}, 100.0))

    def test_default_pct_needs_whole_family(self) -> None:
        # At 100 one surviving target keeps the family up; both dead fails it.
        self.assertTrue(self.verdict("2606:4700:4700::1111", pct=100))
        self.assertFalse(self.verdict(*self.V6, pct=100))

    def test_pct_50_trips_on_half_a_family(self) -> None:
        # Half of a 2-target family is 50%, so one dead target is enough.
        self.assertFalse(self.verdict("2606:4700:4700::1111", pct=50))
        self.assertTrue(self.verdict(pct=50))

    def test_pct_boundary_is_inclusive(self) -> None:
        # failing share == pct counts as down (>=, not >).
        oks = [True, False]  # exactly 50% failing
        self.assertEqual(family_failing_pct(oks), 50.0)
        self.assertFalse(
            family_results({"1.1.1.1": True, "8.8.8.8": False}, 50)["ipv4"]
        )
        self.assertTrue(
            family_results({"1.1.1.1": True, "8.8.8.8": False}, 50.1)["ipv4"]
        )

    def test_pct_applies_per_family_not_across_all(self) -> None:
        # Both v4 targets dead is 100% of v4 but only 50% of everything; the
        # family view is what must trip, which a flat rule would miss.
        self.assertFalse(self.verdict(*self.V4, pct=100))

    def test_low_pct_trips_on_a_single_target(self) -> None:
        for target in self.V4 + self.V6:
            self.assertFalse(self.verdict(target, pct=1), target)

    def test_family_failing_pct_values(self) -> None:
        self.assertEqual(family_failing_pct([]), 0.0)
        self.assertEqual(family_failing_pct([True, True]), 0.0)
        self.assertEqual(family_failing_pct([True, False]), 50.0)
        self.assertEqual(family_failing_pct([False, False]), 100.0)
        self.assertAlmostEqual(family_failing_pct([False, True, True]), 100 / 3)

    def test_thirds_do_not_trip_at_100(self) -> None:
        # Float division must not let 2/3 failing read as 100%.
        results = {"1.1.1.1": False, "8.8.8.8": False, "9.9.9.9": True}
        self.assertTrue(round_verdict(results, 100.0))
        results["9.9.9.9"] = False
        self.assertFalse(round_verdict(results, 100.0))

    def test_unparseable_target_is_its_own_family(self) -> None:
        results = {"1.1.1.1": True, "2606:4700:4700::1111": True, "host": False}
        self.assertFalse(round_verdict(results, 100.0))
        results["host"] = True
        self.assertTrue(round_verdict(results, 100.0))


class ProbeVerdictIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_probe_round_maps_targets(self) -> None:
        settings = make_settings()

        async def fake_probe(interface: str, target: str) -> bool:
            return target.endswith("1.1.1.1") or target.startswith("2606")

        with mock.patch.object(probe, "probe_target", new=fake_probe):
            results = await probe_round(settings)
        self.assertEqual(
            results,
            {
                "1.1.1.1": True,
                "8.8.8.8": False,
                "2606:4700:4700::1111": True,
                "2001:4860:4860::8888": False,
            },
        )
        self.assertTrue(round_verdict(results, 100.0))
