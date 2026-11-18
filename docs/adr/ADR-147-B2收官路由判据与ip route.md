# ADR-147：B2 最后一刀——路由判据、`ip route` 与 DHCP 掩码/网关

状态：采纳（2026-11-18，证据来源 / 总设计阶段 B2 / **零新号**）
关联：ADR-139（ARP）、ADR-142/146（ARP 表与被动学习）、
ADR-143/144/145（ping、`ip link`/`addr`、`ip neigh`）、
总设计《Aurora-OS-完整操作系统架构与Shell命令体系建设总设计-V1.0》§阶段 B2

> 写作纪律：已采纳 ADR 与有测试证据的事实优先于本文的目标设计；发现冲突先记差异，
> 不要为了让文档一致去改已经验证的结论。每条结论标「实测」或「推断」。

## 背景

前面几刀把 `ping` 与 ARP 都做通了，但**目标 MAC 一直是硬编码的网关**——
`ping 10.0.2.2` 恰好是网关所以歪打正着，`ping 10.0.2.3`（DNS）在同一 /24 里
也该直接 ARP 目标而不是网关，而 `ping 192.168.1.1`（外部）才该走网关。
**没有路由判据，这三者分不出来**。

## 决策

### 决策 1：掩码与网关从 DHCP 读，不从常量猜

`parse_reply` 现在解析两个新 option：

- **option 1 子网掩码**（4 字节）
- **option 3 路由器列表**（取第一个地址作为默认网关）

**长度先验**：option 的 `ln` 不合形状（掩码不是 4、路由器 < 4）就不学，
保持 0.0.0.0（"没给"），**不猜默认值**。
`NET_SUBNET_MASK = [255,255,255,0]` 是**显式回退**，来路是
`-netdev user,net=10.0.2.0/24` 的启动参数（和 `DHCP_GUEST_IP` 同一来源），
不是凭空写下的"常识"。

### 决策 2：路由判据是纯函数，用 ktest 而不是网络用例判它

`virtio::is_local_subnet(our, mask, dst) -> bool` 与
`next_hop(our, mask, dst) -> [u8;4]`：

- 同子网 → 下一跳 = 目标自己（直接 ARP）
- 外部 → 下一跳 = 网关

**路由是算术，不是网络**：把它放进网络用例判会被网络抖动污染，
所以单开一个 ktest `t_net_route` 六格（同子网/跨子网/自己/广播/全 0 掩码/⦸32 掩码），
不发一帧。实测六格全 true，88/88 全绿。

**⦸0 掩码的退化分支**只有 [同一个 IP] 算本子网——这是**退化的选择**
而不是"正确"：掩码 0 的语义有两种读法，这里取"无子网 = 只能自己"。

### 决策 3：用户态镜像而不是新号

runtime 加 `is_local_subnet` / `next_hop` 的镜像（同形状），shell 的
`cmd_ping` 用 `next_hop` 决定 ARP 谁：

```
let hop = rt::next_hop(&our_ip, &mask, &ip, &gateway);
let arp = rt::net_build_arp(&our_mac, &our_ip, &hop);
```

**为什么不做 `SYS_NET_ROUTE` 号**：内核已经有了，用户态只要两个 u8 数组的
按位与——为一个 6 行算术开一个 syscall 是过度设计。两份实现由同一个 ktest
与同一份掩码常量作证（ADR-146 的"被动学习"已经让两条 ARP 实现共享一张表）。

### 决策 4：`ip route` 是只读展示，不引入路由表

今天只有**一条默认路由**（网关），所以 `ip route` 打一行：

```
route default via 10.0.2.2
```

判定格 `_ip_route_row` 只验形状与"是一个合法 IPv4"，不验具体网关值。

## 落地时撞到的事（实测）

1. **`ip route` 分支放在 `info` 取值之前** ⇒ E0425 `cannot find value info`。
   **修**：移到 `info` 之后，并把 `!want_link && !want_addr` 的 usage 守卫
   改成也允许 `is_route`。
2. **变异证红一度"假绿"**：删掉 `ip route` 输出行后，单独的 `run` 仍 PASS，
   因为判定格虽然通过了函数自测，但我没重新走 `test` 的 `ash_ok` 组合。
   **修**：用整链跑变异，得到 `CONTENT-MISMATCH`（实测）才确认判定格真的接上。
   **教训**：判据的"会红"要在**整链判定级**证，不能只看辅助函数返回值。
3. 我的 Python 写入又把中文注释写成双重编码两次——按行 `latin-1 → utf-8`
   逆转清零（这是本会话第三次同类错误）。

## 验收与负样本

**实测**（a3-shell，PASS(33) 14.9s，串口逐行）：

```
ping 10.0.2.2      -> from 10.0.2.2: seq=1
ip neigh           -> 10.0.2.2 52:55:0a:00:02:02
ip route           -> route default via 10.0.2.2
```

`ip` 四子命令（`link`/`addr`/`neigh`/`route`）全齐。

- **路由 ktest 变异证红**：`next_hop` 恒返回网关 ⇒ `自己=false`、FAIL(35)，
  还原 ⇒ 六格全 true（实测）。
- **`ip route` 判定变异证红**：删掉输出行 ⇒ 整链 `CONTENT-MISMATCH`，
  还原 ⇒ 绿（实测）。
- `check` 18/18；整链 70 符合 + 3 条不符（都是已知抖动族：
  `日志尾` HANG 因那跑串口无 fail/fatal 行、FS-03 两条因 `t_fat32` 卷抖动），
  **单跑复验全部通过**：`fault-crash-oops` EXCEPTION(39) + log tail 4/4 相符、
  `fat32-probe` PASS。

## 影响

正面：B2 验收句的 `ping` 与 `ip` 命令族四个子命令全部达成；
路由判据让"同子网 vs 外部"第一次有结构性区分；DHCP 掩码/网关从线上读。

负面：**只有一条默认路由**（无路由表、无最长前缀匹配）；**用户态掩码硬编码**
`[255,255,255,0]`（DHCP 已解析出来但没传到用户态——35 号读数块没带掩码，
下次扩 35 号时可以补）；**TCP 三次握手**仍未做。

## 迁移与回滚

零新号。回滚 = 删 `is_local_subnet`/`next_hop`（内核+用户态）、`t_net_route`、
`ip route` 分支与 `_ip_route_row` 格、DHCP option 解析的两个字段。

## 未决

1. **把 DHCP 掩码传到用户态**（扩 35 号读数块到 28 字节，加 mask4），
   去掉 shell 侧硬编码。
2. **路由表**：多网卡/多前缀时的最长前缀匹配。
3. **TCP**：三次握手 + 重传 + 序号/窗口——比 UDP 重一个量级，单独 ADR。
