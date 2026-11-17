"""路由模拟器：按顺序评估 import/export 策略链并记录完整 trace。"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional

from .model import Network, Peer, Route


@dataclass
class TraceEvent:
    stage: str            # "import" / "export"
    peer: str
    route_map: Optional[str]
    seq: Optional[int]
    action: str           # permit / deny / implicit-deny / as-loop / split-horizon / attr
    detail: str = ""

    def location(self) -> str:
        if self.route_map is None:
            return f"peer {self.peer} {self.stage} ({self.action})"
        return f"peer {self.peer} {self.stage} route-map {self.route_map} seq {self.seq}"


@dataclass
class SimResult:
    route: Optional[Route]
    trace: list = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.route is not None

    def first_permit_location(self, stage: Optional[str] = None) -> Optional[str]:
        """首个放行该路由的规则位置（首个偏离点），可按阶段过滤。"""
        for event in self.trace:
            if event.action == "permit" and (stage is None
                                             or event.stage == stage):
                return event.location()
        return None


class Simulator:
    def __init__(self, network: Network):
        self.net = network

    def _apply_chain(self, chain, route, peer, stage, trace) -> Optional[Route]:
        for rm_name in chain:
            rm = self.net.route_maps[rm_name]
            matched_any = False
            for entry in rm.ordered_entries():
                if not entry.matches(route, self.net):
                    continue
                matched_any = True
                if entry.action == "deny":
                    trace.append(TraceEvent(stage, peer.name, rm_name, entry.seq,
                                            "deny", "matched deny entry"))
                    return None
                route, changes = entry.apply(route, self.net)
                detail = "; ".join(changes) if changes else "no attribute change"
                trace.append(TraceEvent(stage, peer.name, rm_name, entry.seq,
                                        "permit", detail))
                break
            if not matched_any:
                trace.append(TraceEvent(stage, peer.name, rm_name, None,
                                        "implicit-deny",
                                        "no entry matched, implicit deny"))
                return None
        return route

    def import_route(self, peer: Peer, route: Route) -> SimResult:
        trace = []
        r = route
        if peer.session == "ebgp":
            if self.net.local_asn in r.as_path:
                trace.append(TraceEvent("import", peer.name, None, None,
                                        "as-loop", "local ASN in AS path"))
                return SimResult(None, trace)
            if r.local_pref is None:
                r = replace(r, local_pref=100)
                trace.append(TraceEvent("import", peer.name, None, None,
                                        "attr", "default local-pref=100"))
        r = self._apply_chain(peer.import_chain, r, peer, "import", trace)
        return SimResult(r, trace)

    def export_route(self, peer: Peer, route: Route,
                     source: Optional[Peer] = None) -> SimResult:
        trace = []
        r = route
        if peer.session == "ibgp":
            if source is not None and source.session == "ibgp":
                allowed = self.net.is_route_reflector and (
                    source.role == "rr-client" or peer.role == "rr-client")
                if not allowed:
                    trace.append(TraceEvent("export", peer.name, None, None,
                                            "split-horizon",
                                            "iBGP route not re-advertised to iBGP"))
                    return SimResult(None, trace)
        else:
            r = replace(r, as_path=(self.net.local_asn,) + r.as_path,
                        local_pref=None)
            trace.append(TraceEvent("export", peer.name, None, None, "attr",
                                    f"prepend local AS {self.net.local_asn}; "
                                    "strip local-pref"))
        r = self._apply_chain(peer.export_chain, r, peer, "export", trace)
        return SimResult(r, trace)

    def propagate(self, source: Peer, route: Route,
                  target: Peer) -> SimResult:
        """完整路径：从 source 导入，再向 target 导出，trace 合并。"""
        inbound = self.import_route(source, route)
        if not inbound.accepted:
            return inbound
        outbound = self.export_route(target, inbound.route, source=source)
        return SimResult(outbound.route, inbound.trace + outbound.trace)
