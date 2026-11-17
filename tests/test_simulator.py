"""模拟器行为测试：eBGP/iBGP、RR、策略顺序、空过滤器、属性传播。"""

import unittest

from bgplinter.model import (
    CommunityList,
    CommunityListEntry,
    Network,
    Peer,
    PrefixList,
    Route,
    RouteMap,
    RouteMapEntry,
)
from bgplinter.simulator import Simulator

from tests.helpers import base_network, safe_network


class TestEbgpImportExport(unittest.TestCase):
    def test_import_applies_set_clauses(self):
        net = base_network(
            export_entries=(),
            import_entries=(
                RouteMapEntry(10, "permit", match_prefix_list="PL-CUSTOMER",
                              set_local_pref=200,
                              set_as_path_prepend=(65000, 65000),
                              set_community=("65000:100",)),
            ),
        )
        sim = Simulator(net)
        result = sim.import_route(net.peers["cust1"],
                                  Route("203.0.113.0/24", as_path=(65001,)))
        self.assertTrue(result.accepted)
        r = result.route
        self.assertEqual(r.local_pref, 200)
        self.assertEqual(r.as_path, (65000, 65000, 65001))
        self.assertIn("65000:100", r.communities)
        details = " ".join(e.detail for e in result.trace)
        self.assertIn("as-prepend", details)
        self.assertIn("local-pref=200", details)
        self.assertIn("community-add", details)

    def test_ebgp_export_prepends_and_strips_local_pref(self):
        net = safe_network()
        sim = Simulator(net)
        result = sim.export_route(
            net.peers["transit1"],
            Route("203.0.113.0/24", as_path=(65001,), local_pref=200))
        self.assertTrue(result.accepted)
        self.assertEqual(result.route.as_path, (65000, 65001))
        self.assertIsNone(result.route.local_pref)

    def test_as_loop_rejected_on_import(self):
        net = safe_network()
        sim = Simulator(net)
        result = sim.import_route(
            net.peers["cust1"],
            Route("203.0.113.0/24", as_path=(65001, 65000)))
        self.assertFalse(result.accepted)
        self.assertEqual(result.trace[-1].action, "as-loop")

    def test_implicit_deny_recorded(self):
        net = base_network(export_entries=(), import_entries=(
            RouteMapEntry(10, "permit", match_prefix_list="PL-CUSTOMER"),
        ))
        sim = Simulator(net)
        result = sim.import_route(net.peers["cust1"],
                                  Route("8.8.8.0/24", as_path=(65001,)))
        self.assertFalse(result.accepted)
        self.assertEqual(result.trace[-1].action, "implicit-deny")

    def test_default_local_pref_on_ebgp_import(self):
        net = safe_network()
        sim = Simulator(net)
        result = sim.import_route(net.peers["cust1"],
                                  Route("203.0.113.0/24", as_path=(65001,)))
        self.assertTrue(result.accepted)
        self.assertEqual(result.route.local_pref, 100)


class TestIbgpAndRouteReflector(unittest.TestCase):
    def _ibgp_net(self, is_rr):
        net = safe_network()
        peers = dict(net.peers)
        peers["core1"] = Peer("core1", 65000, "internal", "ibgp")
        peers["core2"] = Peer("core2", 65000, "internal", "ibgp")
        peers["rrc1"] = Peer("rrc1", 65000, "rr-client", "ibgp")
        return Network(local_asn=net.local_asn, peers=peers,
                       prefix_lists=net.prefix_lists,
                       as_path_filters=net.as_path_filters,
                       community_lists=net.community_lists,
                       route_maps=net.route_maps, is_route_reflector=is_rr)

    def test_ibgp_export_keeps_attributes(self):
        net = self._ibgp_net(is_rr=False)
        sim = Simulator(net)
        result = sim.export_route(
            net.peers["core1"],
            Route("203.0.113.0/24", as_path=(65001,), local_pref=200),
            source=net.peers["cust1"])
        self.assertTrue(result.accepted)
        self.assertEqual(result.route.as_path, (65001,))
        self.assertEqual(result.route.local_pref, 200)

    def test_ibgp_split_horizon_blocks_readvertise(self):
        net = self._ibgp_net(is_rr=False)
        sim = Simulator(net)
        result = sim.export_route(
            net.peers["core2"],
            Route("203.0.113.0/24", as_path=(), local_pref=100),
            source=net.peers["core1"])
        self.assertFalse(result.accepted)
        self.assertEqual(result.trace[-1].action, "split-horizon")

    def test_route_reflector_reflects_client_routes(self):
        net = self._ibgp_net(is_rr=True)
        sim = Simulator(net)
        route = Route("203.0.113.0/24", as_path=(), local_pref=100)
        self.assertTrue(sim.export_route(
            net.peers["core1"], route,
            source=net.peers["rrc1"]).accepted)
        self.assertTrue(sim.export_route(
            net.peers["rrc1"], route,
            source=net.peers["core1"]).accepted)
        self.assertFalse(sim.export_route(
            net.peers["core2"], route,
            source=net.peers["core1"]).accepted)


class TestPolicyOrderAndEmptyFilters(unittest.TestCase):
    def test_entry_order_changes_outcome(self):
        entries = (
            RouteMapEntry(10, "permit", match_prefix_list="PL-CUSTOMER"),
            RouteMapEntry(20, "deny", match_prefix_list="PL-CUSTOMER"),
        )
        net = base_network(export_entries=entries)
        sim = Simulator(net)
        route = Route("203.0.113.0/24", as_path=(65001,))
        self.assertTrue(sim.export_route(net.peers["transit1"], route).accepted)
        swapped = (
            RouteMapEntry(20, "permit", match_prefix_list="PL-CUSTOMER"),
            RouteMapEntry(10, "deny", match_prefix_list="PL-CUSTOMER"),
        )
        net2 = base_network(export_entries=swapped)
        sim2 = Simulator(net2)
        self.assertFalse(sim2.export_route(net2.peers["transit1"],
                                           route).accepted)

    def test_empty_prefix_list_denies_everything(self):
        net = base_network(
            export_entries=(RouteMapEntry(10, "permit",
                                          match_prefix_list="PL-EMPTY"),),
            prefix_lists={"PL-EMPTY": PrefixList("PL-EMPTY", ())},
        )
        sim = Simulator(net)
        result = sim.export_route(net.peers["transit1"],
                                  Route("203.0.113.0/24", as_path=(65001,)))
        self.assertFalse(result.accepted)
        self.assertEqual(result.trace[-1].action, "implicit-deny")

    def test_empty_route_map_denies_all(self):
        net = base_network(
            export_entries=(),
            extra_route_maps={"RM-EMPTY": RouteMap("RM-EMPTY", ())},
        )
        peers = dict(net.peers)
        t = peers["transit1"]
        peers["transit1"] = Peer(t.name, t.asn, t.role, t.session,
                                 t.import_chain, ("RM-EMPTY",))
        net = Network(local_asn=net.local_asn, peers=peers,
                      prefix_lists=net.prefix_lists,
                      as_path_filters=net.as_path_filters,
                      community_lists=net.community_lists,
                      route_maps=net.route_maps)
        sim = Simulator(net)
        result = sim.export_route(net.peers["transit1"],
                                  Route("203.0.113.0/24", as_path=(65001,)))
        self.assertFalse(result.accepted)
        self.assertEqual(result.trace[-1].action, "implicit-deny")

    def test_community_delete_and_none(self):
        net = base_network(
            export_entries=(),
            import_entries=(
                RouteMapEntry(10, "permit",
                              delete_community_list="CL-DEL"),
            ),
            community_lists={
                "CL-DEL": CommunityList("CL-DEL", (
                    CommunityListEntry("permit", "65000:666"),
                )),
            },
        )
        sim = Simulator(net)
        route = Route("203.0.113.0/24", as_path=(65001,),
                      communities=frozenset({"65000:666", "65000:1"}))
        result = sim.import_route(net.peers["cust1"], route)
        self.assertTrue(result.accepted)
        self.assertEqual(result.route.communities, frozenset({"65000:1"}))
        net2 = base_network(
            export_entries=(),
            import_entries=(RouteMapEntry(10, "permit",
                                          set_community_none=True),),
        )
        result2 = Simulator(net2).import_route(net2.peers["cust1"], route)
        self.assertEqual(result2.route.communities, frozenset())


if __name__ == "__main__":
    unittest.main()
