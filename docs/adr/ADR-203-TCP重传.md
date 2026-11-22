# ADR-203：TCP 重传

状态：**已采纳**（2026-11-22：`t_tcp_retx` 九格全 true）

关联：ADR-201（定时器）、ADR-202（中断下半部）、ADR-200（TCP syscall 路径）

> **这是定时器、下半部、TCP 三层第一次真正串起来。**
>
> 前两层在此之前都只是「零件」—— 判据在调它们，但没有真实业务消费者。

## 拆掉的天花板

前面几片一直记着一条：**「TCP 丢一个段就永久卡住」**。

这一层把它拆掉。

## 交付

```rust
pub struct RetxState { seq, len, flags, tries, backoff_us, armed }
pub const RETX_BASE_US: u32 = 200_000;        // 200 ms
pub const RETX_MAX_BACKOFF_US: u32 = 3_200_000;  // 3.2 s
pub const RETX_MAX_TRIES: u8 = 6;

ConnState::arm_retx(seq, len, flags)
ConnState::ack_retx(ack) -> bool
ConnState::on_retx_timeout() -> Option<Reply>

socket::tcp_handle_timer(kind, token) -> Option<(slot, gen, Reply)>
socket::tcp_arm_retx_timer(slot) -> Option<u16>
```

## 决策

### 决策 1：重传**不推进 `snd_nxt`**

**这是重传与正常发送最关键的差别，也是最容易写错的地方。**

重传发的是**同一段数据**（同样的 seq、同样的载荷、同样的标志）。推进序号会让对端
看到「跳过一个段」，而那个缺口永远补不上。

这条判据在第 4 格，负样本就是让它推进一次 —— 实测 `5000->5100` 当场红。

### 决策 2：ACK 判据用 `ack >= seq + len`，不是 `==`

真实 TCP 的 ACK 可以累积确认。今天只发一段，`==` 也对；但 `>=` 是**更安全**的写法 ——
它不会因为对端回了更大的 ack（重复确认）而漏掉取消。

序号回绕用 `ack.wrapping_sub(end) < 0x8000_0000` 判。

### 决策 3：固定 200 ms 起步，指数退避到 3.2 s

**真实 TCP 用 RTT 估计算 RTO。今天没有 RTT 测量 ⇒ 用固定值。**

而固定值在网络抖动时会误判 —— 这是本 ADR 明确记下的取舍，不是疏忽。

6 次 × 退避累计约 9.4 s 就放弃。Linux 的 `tcp_retries2` 默认 15（分钟级），
而本仓库的判据不能等那么久。

### 决策 4：只记**一段**，不是队列

`RetxState` 只有一条。真实 TCP 有重传队列（可能同时有多个未确认段）。

**这是真实的能力缺失**：连续发两段时，第一段的重传记录会被第二段覆盖。

**为什么今天可以接受**：`tcp_send_payload` 是「发一段等一段」的语义 —— 调用方
通常发完就等 ACK。已写进未决 1。

## 判据九格（`t_tcp_retx`）

```
retx: arm=true ACK取消=true 部分ACK不取消=true 不推进=true 退避=true
      放弃=true 分派=true 不误伤=true 端到端=true ⇒ true
```

## 负样本（变异证红）

让 `on_retx_timeout` 推进 `snd_nxt`：

```
retx: 重传推进了 snd_nxt 5000->5100
retx: ... 不推进=false ⇒ false
```

## 一个判据自己写错的地方

第 5 格（退避）第一版循环 10 次想「一直翻倍到封顶」，实测：

```
retx: 退避不对 200000 400000 800000 max=0
```

**`max=0` 不是退避错** —— `tries` 到 `RETX_MAX_TRIES`(6) 就放弃，`armed` 被清、
`backoff` 归零。

改成正好 4 次（200ms → 400 → 800 → 1600 → 3200 = 封顶）就对。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | `t_tcp_retx` 九格全绿 |

## 三层第一次串起来的形状

```
定时器到期（ADR-201 的 advance/expire）
  ↓
下半部投递（ADR-202 的 post → drain）
  ↓
tcp_handle_timer(kind, token)   ← **这一层新加的接缝**
  ↓
ConnState::on_retx_timeout()     → 拿到要重发的段
  ↓
调用方装帧发出
```

## 未决

1. **重传队列**（现在只记一段）
2. **RTT 测量与自适应 RTO**（现在固定 200 ms）
3. **快速重传**（三个重复 ACK 立即重传，不等超时）
4. **`drain` 之后真的要发出去** —— 判据走的是 `tcp_handle_timer` 直接调用，
   真实路径需要「有一个线程在 `drain` 并把段发出去」，那还没做
5. **没有定时器时怎么办** —— `tcp_arm_retx_timer` 在时钟未标定时回 `None`，
   调用方应当知道「这条连接没有重传保护」