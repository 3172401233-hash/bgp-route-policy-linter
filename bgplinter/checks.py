"""安全审计：在完整策略链模拟的基础上发现路由泄露与策略缺陷。

每个 Finding 都附带一条反例路由、其 AS path 和首个偏离规则的位置。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .model import (
    DEFAULT_ROUTE,
    RESERVED_NETWORKS,
    Network,
    Route,
    RouteMapEntry,
)
from .simulator import Simulator


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    counterexample: Route
    first_divergence: str

    def __str__(self) -> str:
        return (f"[{self.severity}] {self.check}: {self.message}\n"
                f"  counterexample: prefix={self.counterexample.prefix} "
                f"as_path={list(self.counterexample.as_path)} "
                f"communities={sorted(self.counterexample.communities)}\n"
                f"  first divergence: {self.first_divergence}")


def _witness_for_entry(entry: RouteMapEntry, net: Network,
                       peer_asn: int = 65001) -> Route:
    """为某条 route-map 条目构造一条必然命中它的反例路由。"""
    prefix = "198.51.100.0/24"
    if entry.match_prefix_list is not None:
        pl = net.prefix_lists[entry.match_prefix_list]
        for ple in pl.entries:
            if ple.action != "permit":
                continue
            plen = max(ple.ge or 0, int(ple.prefix.split("/")[1]))
            net_obj = ipaddress.ip_network(ple.prefix)
            prefix = str(next(net_obj.subnets(new_prefix=plen)))
            break
    as_path = (peer_asn,)
    if entry.match_as_path is not None:
        asns = [int(x) for x in re.findall(
            r"\d+", net.as_path_filters[entry.match_as_path].regex)]
        if asns:
            as_path = tuple(asns)
    communities = frozenset()
    if entry.match_community is not None:
        communities = net.community_lists[entry.match_community].permitted()
    return Route(prefix=prefix, as_path=as_path, communities=communities)


def _source_peers(net: Network) -> list:
    return [p for p in net.peers.values() if p.session == "ebgp"]


def check_prefix_leak(net: Network, prefixes, check_name, label) -> list:
    """通用泄露检查：候选前缀经任意 eBGP 源导入后能到达 transit/peer。"""
    sim = Simulator(net)
    findings = []
    for target in net.external_peers():
        for prefix in prefixes:
            hit = None
            for source in _source_peers(net):
                if source.name == target.name:
                    continue
                route = Route(prefix=prefix, as_path=(source.asn, 65001))
                result = sim.propagate(source, route, target)
                if result.accepted:
                    hit = (source, result)
                    break
            if hit:
                source, result = hit
                findings.append(Finding(
                    check=check_name,
                    severity="high",
                    message=(f"{label} {prefix} 从 {source.name} 导入后被泄露给 "
                             f"{target.role} 邻居 {target.name}"),
                    counterexample=result.route,
                    first_divergence=(
                        result.first_permit_location(stage="export")
                        or result.first_permit_location() or "unknown"),
                ))
    return findings


def check_private_prefix_leak(net: Network) -> list:
    candidates = list(RESERVED_NETWORKS)
    candidates += ["10.1.2.0/24", "172.16.9.0/24", "192.168.100.0/24"]
    return check_prefix_leak(net, candidates,
                             "private-prefix-leak", "私网/保留前缀")


def check_default_route_leak(net: Network) -> list:
    return check_prefix_leak(net, [DEFAULT_ROUTE],
                             "default-route-leak", "默认路由")


def check_unconditional_permit(net: Network) -> list:
    """export 链上无 match 条件的 permit 条目会放行一切路由到 transit。"""
    sim = Simulator(net)
    findings = []
    for peer in net.external_peers():
        for rm_name in peer.export_chain:
            for entry in net.route_maps[rm_name].ordered_entries():
                if entry.action == "permit" and not entry.match_spec():
                    route = Route(prefix="10.0.0.0/8", as_path=(65001,))
                    result = sim.export_route(peer, route)
                    findings.append(Finding(
                        check="unconditional-permit",
                        severity="high",
                        message=(f"peer {peer.name} export route-map {rm_name} "
                                 f"seq {entry.seq} 为无条件 permit，"
                                 f"任意路由都可到达 {peer.role} 邻居"),
                        counterexample=result.route or route,
                        first_divergence=(
                            f"peer {peer.name} export route-map {rm_name} "
                            f"seq {entry.seq}"),
                    ))
    return findings


def check_shadowed_deny(net: Network) -> list:
    """靠前的 permit 分支完全覆盖后续 deny，使 deny 永远不可达。"""
    findings = []
    for rm in net.route_maps.values():
        entries = rm.ordered_entries()
        for i, deny in enumerate(entries):
            if deny.action != "deny":
                continue
            deny_spec = deny.match_spec()
            for earlier in entries[:i]:
                if earlier.action != "permit":
                    continue
                permit_spec = earlier.match_spec()
                # permit 的约束是 deny 约束的子集 => permit 完全覆盖 deny
                if all(deny_spec.get(k) == v for k, v in permit_spec.items()):
                    witness = _witness_for_entry(deny, net)
                    findings.append(Finding(
                        check="shadowed-deny",
                        severity="medium",
                        message=(f"route-map {rm.name} seq {deny.seq} 的 deny "
                                 f"被 seq {earlier.seq} 的 permit 完全覆盖，"
                                 f"永远不会生效"),
                        counterexample=witness,
                        first_divergence=(
                            f"route-map {rm.name} seq {earlier.seq}"),
                    ))
                    break
    return findings


def check_community_strip_bypass(net: Network) -> list:
    """import 链剥离 community 后，export 侧依赖该 community 的 deny 被绕过。"""
    sim = Simulator(net)
    # 收集 import 链上的 community 剥离点：(peer, community 或 None=全部, 位置)
    strippers = []
    for peer in net.peers.values():
        for rm_name in peer.import_chain:
            for entry in net.route_maps[rm_name].ordered_entries():
                loc = (f"peer {peer.name} import route-map {rm_name} "
                       f"seq {entry.seq}")
                if entry.set_community_none:
                    strippers.append((peer, None, loc))
                if entry.delete_community_list is not None:
                    cl = net.community_lists[entry.delete_community_list]
                    for comm in cl.permitted():
                        strippers.append((peer, comm, loc))
    findings = []
    for target in net.external_peers():
        for rm_name in target.export_chain:
            for entry in net.route_maps[rm_name].ordered_entries():
                if entry.action != "deny" or entry.match_community is None:
                    continue
                guard = net.community_lists[entry.match_community]
                for comm in guard.permitted():
                    for src_peer, stripped, loc in strippers:
                        if src_peer.name == target.name:
                            continue
                        if stripped is not None and stripped != comm:
                            continue
                        route = Route(prefix="8.8.8.0/24",
                                      as_path=(src_peer.asn, 65001),
                                      communities=frozenset({comm}))
                        result = sim.propagate(src_peer, route, target)
                        if result.accepted:
                            findings.append(Finding(
                                check="community-strip-bypass",
                                severity="high",
                                message=(f"community {comm} 在 {loc} 被剥离，"
                                         f"绕过 peer {target.name} export "
                                         f"route-map {rm_name} seq {entry.seq} "
                                         f"的 deny，路由泄露给 {target.name}"),
                                counterexample=result.route,
                                first_divergence=loc,
                            ))
    return findings


def run_all_checks(net: Network) -> list:
    findings = []
    findings += check_private_prefix_leak(net)
    findings += check_default_route_leak(net)
    findings += check_unconditional_permit(net)
    findings += check_shadowed_deny(net)
    findings += check_community_strip_bypass(net)
    return findings
