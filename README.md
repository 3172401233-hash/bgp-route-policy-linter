# bgp-route-policy-linter
Python BGP 路由策略安全审计库，处理前缀过滤、路由泄露、community 和策略顺序

## 功能

在同一机房、多邻居角色（customer / peer / transit / rr-client）的场景下，
把每条 peer 的**完整有序策略链**（import/export route-map 序列）整体求值，
模拟一条路由从导入到再次导出的最终状态，而不是孤立地检查单条 route-map。

模拟过程会记录完整 trace：

- `as-prepend`、`local-pref`、community 增删等属性变更
- 默认路由（`0.0.0.0/0`）与隐式 deny 的传播结果
- eBGP 导出时的本 AS prepend 与 local-pref 剥离
- iBGP 水平分割与 route reflector 反射规则

## 安全检查

`run_all_checks(network)` 返回 `Finding` 列表，每个 finding 都附带
**反例路由、AS path 和首个偏离规则的位置**：

| 检查 | 说明 |
| --- | --- |
| `private-prefix-leak` | 私网/保留前缀（RFC1918、CGN、loopback 等）经任意源导入后泄露给 transit/peer |
| `default-route-leak` | 默认路由被误发布到 transit/peer |
| `unconditional-permit` | export 链上无 match 条件的 permit 放行一切路由 |
| `shadowed-deny` | 靠前的 permit 分支完全覆盖后续 deny，使其永远不可达 |
| `community-strip-bypass` | import 链剥离 community 后，export 侧依赖该 community 的 deny 被绕过 |

## 用法

```python
from bgplinter import (Network, Peer, PrefixList, PrefixListEntry,
                       RouteMap, RouteMapEntry, run_all_checks)

net = Network(
    local_asn=65000,
    prefix_lists={"PL-PRIVATE": PrefixList("PL-PRIVATE", (
        PrefixListEntry("permit", "10.0.0.0/8", le=32),
    ))},
    route_maps={"RM-OUT": RouteMap("RM-OUT", (
        RouteMapEntry(10, "deny", match_prefix_list="PL-PRIVATE"),
        RouteMapEntry(20, "permit"),
    ))},
    peers={
        "cust1": Peer("cust1", 65001, "customer", "ebgp"),
        "transit1": Peer("transit1", 1299, "transit", "ebgp",
                         export_chain=("RM-OUT",)),
    },
)
for finding in run_all_checks(net):
    print(finding)
```

## 模型假设

- **AS path 表示**：元组，最左侧为最近经过的 AS；eBGP 导出时自动 prepend
  本 AS，eBGP 导入时检查 AS loop。
- **route-map 语义**：条目按 seq 升序评估，首个命中条目生效；permit 命中后
  应用 set 子句并进入链上下一条 route-map；所有条目都未命中 => 隐式 deny。
  空 route-map 拒绝一切；peer 未挂策略链（空链）则直接放行。
- **prefix-list 语义**：无 `ge`/`le` 修饰时精确匹配前缀长度；列表末尾隐式 deny。
- **AS-path 过滤器**：Cisco 风格正则，`_` 表示 AS 边界。
- **local-pref**：eBGP 导入时缺省为 100；iBGP 传播保留；eBGP 导出时剥离。
- **iBGP**：iBGP 学到的路由默认不再转发给 iBGP 邻居（水平分割）；当本机
  `is_route_reflector=True` 时，允许在 rr-client 与非 client 之间反射。
- **community**：`set community none` 清空全部；`delete_community_list`
  删除列表 permit 的 community；export 侧 `match community` 要求路由携带
  对应 community 才命中。
- **泄露判定**：凡能从任一 eBGP 源邻居导入、再经任一 transit/peer 邻居
  导出的候选路由（私网/保留前缀、默认路由）即视为泄露；反例路由为导出后
  的最终形态（含 prepend 后的 AS path）。
- **首个偏离点**：泄露类 finding 取 export 阶段首个放行该路由的规则；
  shadowed-deny 取覆盖它的前序 permit 条目；community-strip-bypass 取
  剥离 community 的 import 条目。

## 测试

```sh
python -m unittest
```

覆盖 eBGP/iBGP 属性传播、route reflector 反射、策略顺序变化、空过滤器
（空 prefix-list / 空 route-map）、community 增删以及全部五类安全检查的
正反例。
