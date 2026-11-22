# ADR-198：TCP 连接状态机

状态：**已采纳**（2026-11-22：`network/tcp_conn.rs` 落地，`tcp-conn` 七格全 true）

关联：ADR-197（TCP 段格式与校验和）

> 切片 G 的**第二层**。**可靠性层还没做**（重传、滑动窗口）。

## 这一层的核心设计：状态机是**纯函数**

```rust
pub fn on_segment(st: &mut ConnState, seg: &Segment) -> Reaction
```

**不持锁、不碰表、不发包。** 输入是「当前状态 + 收到的段」，输出是「新状态 + 要回什么段」。

理由与 ADR-197 同一条：**只有纯函数能被判据完整证伪**。判据可以在一段栈内存上跑完整条
握手与挥手路径 —— 不需要网卡、不需要对端、不需要时序。

## 这解决了一个真实困难

我在上一轮说过：**状态机需要两个端点或一个能回 SYN-ACK 的对端**，而那份工具链不存在。

**纯函数设计绕开了这个问题**：判据自己扮演对端，直接构造段喂给 `on_segment`。

这比「造回环驱动」简单得多，而且**判据更强**（能精确构造「SYN-ACK 的 ack 错一位」这种
真实网络里几乎撞不到的情形）。

## 交付

```rust
pub enum State { Listen, SynSent, SynReceived, Established,
                 FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait }
pub struct ConnState { state, snd_nxt, rcv_nxt, iss, rcv_wnd }
pub enum Reaction { Ignore, Silent, Reply(Reply) }
pub fn on_segment(st, seg) -> Reaction
pub fn close_send_fin(st) -> Option<Reply>
```

## 决策

### 决策 1：`Reaction` 三态，不是 `Option<Reply>`

```rust
pub enum Reaction {
    Ignore,        // 什么都不做（状态也没变）
    Silent,        // 状态变了，但不回段
    Reply(Reply),  // 要回一个段
}
```

`Option` 会把「什么都不做」和「不回但状态变了」混在一起 —— 而那两种在判据里必须分开。

### 决策 2：不做乱序重组

收到的段**必须正好是期望序号**，否则 `Ignore`。

真实 TCP 要缓存乱序段并重组。那是可靠性层的事，不在本 ADR 范围。

### 决策 3：`TimeWait` 是终态

2MSL 定时器没实现。`TimeWait` 之后所有段都 `Ignore`。

**这是一处真实的语义缺失**：真实 TCP 在 `TimeWait` 会重发最后一个 ACK（对端可能没收到）。

## 判据七格（`t_tcp_conn`）

```
tcp-conn: 被动握手=true 主动连接=true 错ACK拒=true 数据=true
          乱序拒=true FIN=true 本端关=true ⇒ true
```

**「错 ACK 拒」这一格是本片最有价值的**：它构造了「SYN-ACK 的 ack = iss+1 之外的值」，
在真实网络上几乎撞不到，而这个校验正是防「连接被劫持」的第一道闸。

## 负样本（变异证红）

把「收到 FIN 时 `rcv_nxt` 前进一格」去掉：

```
tcp-conn: FIN 处理不对 state=CLOSE_WAIT rcv_nxt=1006
tcp-conn: ... FIN=false ⇒ false
```

`rcv_nxt=1006` 而不是 `1007` —— **差一格**，正是 SEQ 占位规则的错法。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | **`PASS(33)`**，`tcp` 与 `tcp-conn` 全绿 |

## 未决

1. **重传**（没有定时器，丢了就丢了）
2. **滑动窗口**（窗口字段照填，但不按对端窗口限制发送）
3. **乱序重组**
4. **TIME_WAIT 重发最后 ACK**
5. **`socket::create(SOCK_STREAM)`** 仍回 `E_NOSYS`（状态机还没接进 socket 层）
6. **拥塞控制**（明确不做）