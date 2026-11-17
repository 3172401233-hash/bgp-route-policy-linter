"""五类安全检查的测试：每类问题都能给出反例，安全配置不产生误报。"""

import unittest

from bgplinter.checks import (
    check_community_strip_bypass,
    check_default_route_leak,
    check_private_prefix_leak,
    check_shadowed_deny,
    check_unconditional_permit,
    run_all_checks,
)
from bgplinter.model import (
    CommunityList,
    CommunityListEntry,
    PrefixList,
    PrefixListEntry,
    RouteMapEntry,
)

from tests.helpers import base_network, safe_network


class TestPrivatePrefixLeak(unittest.TestCase):
    def test_leak_detected_with_counterexample(self):
        # export 只 permit 客户前缀列表，但列表里误加了 10.0.0.0/8
        net = base_network(
            export_entries=(RouteMapEntry(10, "permit",
                                          match_prefix_list="PL-BAD"),),
            prefix_lists={
                "PL-BAD": PrefixList("PL-BAD", (
                    PrefixListEntry("permit", "10.0.0.0/8", le=32),
                    PrefixListEntry("permit", "203.0.113.0/24"),
                )),
            },
        )
        findings = check_private_prefix_leak(net)
        self.assertTrue(findings)
        f = findings[0]
        self.assertTrue(f.counterexample.prefix.startswith("10."))
        self.assertEqual(f.counterexample.as_path[0], 65000)  # 已 prepend 本 AS
        self.assertIn("RM-OUT", f.first_divergence)

    def test_safe_config_has_no_leak(self):
        self.assertEqual(check_private_prefix_leak(safe_network()), [])


class TestDefaultRouteLeak(unittest.TestCase):
    def test_default_route_leak_detected(self):
        net = base_network(
            export_entries=(RouteMapEntry(10, "permit",
                                          match_prefix_list="PL-ANY"),),
            prefix_lists={
                "PL-ANY": PrefixList("PL-ANY", (
                    PrefixListEntry("permit", "0.0.0.0/0", le=32),
                )),
            },
        )
        findings = check_default_route_leak(net)
        self.assertTrue(findings)
        self.assertEqual(findings[0].counterexample.prefix, "0.0.0.0/0")

    def test_safe_config_blocks_default(self):
        self.assertEqual(check_default_route_leak(safe_network()), [])


class TestUnconditionalPermit(unittest.TestCase):
    def test_unconditional_permit_flagged(self):
        net = base_network(
            export_entries=(RouteMapEntry(10, "permit"),))
        findings = check_unconditional_permit(net)
        self.assertEqual(len(findings), 1)
        self.assertIn("seq 10", findings[0].first_divergence)
        self.assertEqual(findings[0].counterexample.prefix, "10.0.0.0/8")

    def test_conditional_permit_not_flagged(self):
        self.assertEqual(check_unconditional_permit(safe_network()), [])


class TestShadowedDeny(unittest.TestCase):
    def test_shadowed_deny_detected(self):
        # seq 10 无条件 permit 完全覆盖 seq 20 的 deny
        net = base_network(export_entries=(
            RouteMapEntry(10, "permit"),
            RouteMapEntry(20, "deny", match_prefix_list="PL-PRIVATE"),
        ))
        findings = check_shadowed_deny(net)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("seq 10", f.first_divergence)
        self.assertTrue(f.counterexample.prefix.startswith("10."))

    def test_correct_order_not_flagged(self):
        net = base_network(export_entries=(
            RouteMapEntry(10, "deny", match_prefix_list="PL-PRIVATE"),
            RouteMapEntry(20, "permit"),
        ))
        self.assertEqual(check_shadowed_deny(net), [])

    def test_narrower_permit_does_not_shadow(self):
        # permit 只覆盖客户前缀，deny 私网仍可达
        net = base_network(export_entries=(
            RouteMapEntry(10, "permit", match_prefix_list="PL-CUSTOMER"),
            RouteMapEntry(20, "deny", match_prefix_list="PL-PRIVATE"),
        ))
        self.assertEqual(check_shadowed_deny(net), [])


class TestCommunityStripBypass(unittest.TestCase):
    def _net_with_strip(self):
        return base_network(
            export_entries=(
                RouteMapEntry(10, "deny", match_community="CL-NOEXPORT"),
                RouteMapEntry(20, "permit"),
            ),
            import_entries=(
                RouteMapEntry(10, "permit", set_community_none=True),
            ),
        )

    def test_strip_bypass_detected(self):
        findings = check_community_strip_bypass(self._net_with_strip())
        self.assertTrue(findings)
        f = findings[0]
        self.assertIn("RM-IN", f.first_divergence)
        self.assertNotIn("65000:666", f.counterexample.communities)

    def test_no_strip_no_bypass(self):
        net = base_network(
            export_entries=(
                RouteMapEntry(10, "deny", match_community="CL-NOEXPORT"),
                RouteMapEntry(20, "permit"),
            ),
            import_entries=(RouteMapEntry(10, "permit"),),
        )
        self.assertEqual(check_community_strip_bypass(net), [])


class TestRunAllChecks(unittest.TestCase):
    def test_clean_network_has_no_findings(self):
        self.assertEqual(run_all_checks(safe_network()), [])

    def test_broken_network_reports_multiple_checks(self):
        net = base_network(export_entries=(RouteMapEntry(10, "permit"),))
        kinds = {f.check for f in run_all_checks(net)}
        self.assertIn("private-prefix-leak", kinds)
        self.assertIn("default-route-leak", kinds)
        self.assertIn("unconditional-permit", kinds)


if __name__ == "__main__":
    unittest.main()
