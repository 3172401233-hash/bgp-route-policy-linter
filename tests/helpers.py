"""测试共用的拓扑构造工具。"""

from bgplinter.model import (
    AsPathFilter,
    CommunityList,
    CommunityListEntry,
    Network,
    Peer,
    PrefixList,
    PrefixListEntry,
    RouteMap,
    RouteMapEntry,
)


def base_network(export_entries, import_entries=None, extra_route_maps=None,
                 is_rr=False, extra_peers=None, prefix_lists=None,
                 community_lists=None):
    """构造一个 customer -> 本 AS -> transit 的最小拓扑。"""
    if import_entries is None:
        import_entries = (RouteMapEntry(10, "permit"),)
    pls = {
        "PL-CUSTOMER": PrefixList("PL-CUSTOMER", (
            PrefixListEntry("permit", "203.0.113.0/24", le=32),
        )),
        "PL-PRIVATE": PrefixList("PL-PRIVATE", (
            PrefixListEntry("permit", "10.0.0.0/8", le=32),
            PrefixListEntry("permit", "172.16.0.0/12", le=32),
            PrefixListEntry("permit", "192.168.0.0/16", le=32),
        )),
    }
    if prefix_lists:
        pls.update(prefix_lists)
    cls = {
        "CL-NOEXPORT": CommunityList("CL-NOEXPORT", (
            CommunityListEntry("permit", "65000:666"),
        )),
    }
    if community_lists:
        cls.update(community_lists)
    rms = {
        "RM-IN": RouteMap("RM-IN", tuple(import_entries)),
        "RM-OUT": RouteMap("RM-OUT", tuple(export_entries)),
    }
    if extra_route_maps:
        rms.update(extra_route_maps)
    peers = {
        "cust1": Peer("cust1", 65001, "customer", "ebgp",
                      import_chain=("RM-IN",), export_chain=()),
        "transit1": Peer("transit1", 1299, "transit", "ebgp",
                         import_chain=(), export_chain=("RM-OUT",)),
    }
    if extra_peers:
        peers.update(extra_peers)
    return Network(local_asn=65000, peers=peers, prefix_lists=pls,
                   community_lists=cls, route_maps=rms,
                   as_path_filters={
                       "ASF-CUST": AsPathFilter("ASF-CUST", "^65001_"),
                   },
                   is_route_reflector=is_rr)


def safe_export_entries():
    """一个安全的 export 策略：deny 私网与默认路由，permit 客户前缀。"""
    return (
        RouteMapEntry(10, "deny", match_prefix_list="PL-PRIVATE"),
        RouteMapEntry(20, "deny", match_prefix_list="PL-DEFAULT"),
        RouteMapEntry(30, "permit", match_prefix_list="PL-CUSTOMER"),
    )


def safe_network():
    from bgplinter.model import PrefixList, PrefixListEntry
    return base_network(
        export_entries=safe_export_entries(),
        prefix_lists={
            "PL-DEFAULT": PrefixList("PL-DEFAULT", (
                PrefixListEntry("permit", "0.0.0.0/0"),
            )),
        },
    )
