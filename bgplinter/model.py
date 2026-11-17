"""策略与拓扑的数据模型。

建模假设（详见 README）：
- AS path 用元组表示，最左侧为最近经过的 AS（与 Cisco 显示顺序一致）。
- AS-path 过滤器使用 Cisco 风格正则，``_`` 表示 AS 边界。
- route-map 条目按 seq 升序评估，首个命中的条目生效；所有 route-map
  评估完后仍未命中任何条目 => 隐式 deny。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from typing import Optional

DEFAULT_ROUTE = "0.0.0.0/0"

#: 私网与保留前缀（RFC1918 / RFC6890 等），不应泄露到公网 transit。
#: 注：TEST-NET 文档前缀（192.0.2.0/24 等）未列入，以便测试拓扑使用。
RESERVED_NETWORKS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

EXTERNAL_ROLES = ("transit", "peer")


@dataclass(frozen=True)
class Route:
    prefix: str
    as_path: tuple = ()
    local_pref: Optional[int] = None
    med: int = 0
    communities: frozenset = frozenset()
    origin: str = "igp"

    def network(self):
        return ipaddress.ip_network(self.prefix)


@dataclass(frozen=True)
class PrefixListEntry:
    action: str  # "permit" / "deny"
    prefix: str
    ge: Optional[int] = None
    le: Optional[int] = None

    def matches(self, prefix: str) -> bool:
        net = ipaddress.ip_network(prefix)
        base = ipaddress.ip_network(self.prefix)
        if net.version != base.version or not net.subnet_of(base):
            return False
        plen = net.prefixlen
        if self.ge is None and self.le is None:
            # 无 ge/le 修饰 => 精确匹配（Cisco 语义）
            return plen == base.prefixlen
        if self.ge is not None and plen < self.ge:
            return False
        if self.le is not None and plen > self.le:
            return False
        return True


@dataclass(frozen=True)
class PrefixList:
    name: str
    entries: tuple = ()

    def matches(self, prefix: str) -> bool:
        """首个命中条目决定结果；无命中 => 隐式 deny。"""
        for entry in self.entries:
            if entry.matches(prefix):
                return entry.action == "permit"
        return False


@dataclass(frozen=True)
class AsPathFilter:
    name: str
    regex: str  # Cisco 风格，"_" 表示 AS 边界

    def matches(self, as_path: tuple) -> bool:
        text = " ".join(str(a) for a in as_path)
        pattern = self.regex.replace("_", r"(?:^|\s|$)")
        return re.search(pattern, text) is not None


@dataclass(frozen=True)
class CommunityListEntry:
    action: str  # "permit" / "deny"
    community: str


@dataclass(frozen=True)
class CommunityList:
    name: str
    entries: tuple = ()

    def permitted(self) -> frozenset:
        return frozenset(e.community for e in self.entries if e.action == "permit")

    def matches(self, communities: frozenset) -> bool:
        return bool(self.permitted() & set(communities))


@dataclass(frozen=True)
class RouteMapEntry:
    seq: int
    action: str  # "permit" / "deny"
    match_prefix_list: Optional[str] = None
    match_as_path: Optional[str] = None
    match_community: Optional[str] = None
    set_local_pref: Optional[int] = None
    set_as_path_prepend: tuple = ()
    set_community: tuple = ()
    set_community_none: bool = False
    delete_community_list: Optional[str] = None

    def match_spec(self) -> dict:
        """返回非空的 match 子句，用于静态覆盖（shadowing）分析。"""
        spec = {}
        if self.match_prefix_list is not None:
            spec["prefix_list"] = self.match_prefix_list
        if self.match_as_path is not None:
            spec["as_path"] = self.match_as_path
        if self.match_community is not None:
            spec["community"] = self.match_community
        return spec

    def matches(self, route: Route, net: "Network") -> bool:
        if self.match_prefix_list is not None:
            pl = net.prefix_lists[self.match_prefix_list]
            if not pl.matches(route.prefix):
                return False
        if self.match_as_path is not None:
            af = net.as_path_filters[self.match_as_path]
            if not af.matches(route.as_path):
                return False
        if self.match_community is not None:
            cl = net.community_lists[self.match_community]
            if not cl.matches(route.communities):
                return False
        return True

    def apply(self, route: Route, net: "Network") -> tuple:
        """应用 set 子句，返回 (新路由, 变更描述列表)。"""
        changes = []
        new = route
        if self.set_local_pref is not None:
            new = replace(new, local_pref=self.set_local_pref)
            changes.append(f"local-pref={self.set_local_pref}")
        if self.set_as_path_prepend:
            new = replace(new, as_path=tuple(self.set_as_path_prepend) + new.as_path)
            changes.append(f"as-prepend={list(self.set_as_path_prepend)}")
        if self.set_community_none:
            if new.communities:
                changes.append(f"community-none(removed={sorted(new.communities)})")
            new = replace(new, communities=frozenset())
        if self.set_community:
            added = set(self.set_community) - set(new.communities)
            new = replace(new, communities=new.communities | frozenset(self.set_community))
            if added:
                changes.append(f"community-add={sorted(added)}")
        if self.delete_community_list is not None:
            cl = net.community_lists[self.delete_community_list]
            removed = set(new.communities) & set(cl.permitted())
            if removed:
                new = replace(new, communities=new.communities - frozenset(removed))
                changes.append(f"community-del={sorted(removed)}")
        return new, changes


@dataclass(frozen=True)
class RouteMap:
    name: str
    entries: tuple = ()

    def ordered_entries(self) -> list:
        return sorted(self.entries, key=lambda e: e.seq)


@dataclass(frozen=True)
class Peer:
    name: str
    asn: int
    role: str  # "customer" / "peer" / "transit" / "rr-client" / "internal"
    session: str  # "ebgp" / "ibgp"
    import_chain: tuple = ()  # 有序 route-map 名称
    export_chain: tuple = ()


@dataclass(frozen=True)
class Network:
    local_asn: int
    peers: dict = field(default_factory=dict)
    prefix_lists: dict = field(default_factory=dict)
    as_path_filters: dict = field(default_factory=dict)
    community_lists: dict = field(default_factory=dict)
    route_maps: dict = field(default_factory=dict)
    is_route_reflector: bool = False

    def external_peers(self) -> list:
        return [p for p in self.peers.values()
                if p.session == "ebgp" and p.role in EXTERNAL_ROLES]
