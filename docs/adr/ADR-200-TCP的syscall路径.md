# ADR-200：TCP 的 syscall 路径（send / recv / accept）

状态：**已采纳**（2026-11-22：`tcpsys` 八格全 true，`PASS(33)`）

关联：ADR-199（TCP 接进 socket 层）、ADR-197（段格式）、ADR-198（状态机）

> 切片 G 的**第四层**，也是最后一块。ADR-199 让 `socket(SOCK_STREAM)` 能建、能收段，
> 但 `sys_sock_send`/`recv` 仍只按 UDP 走，`accept` 是空壳。

## 交付

### 1. `sys_sock_send` 的 TCP 分流

```rust
let (slot, gen) = socket_arg(frame.rdi, owner)?;
// 判据是「这个槽有没有 tcp 状态」，不是「frame 里的 type」—— 后者可伪造
if crate::network::socket::tcp_info(slot, gen).is_some() {
    return tcp_send(slot, gen, frame.rsi, len);
}
```

`tcp_send` 做三件事：取段（推进 `snd_nxt`）、读用户载荷、装 IPv4 帧发出。

### 2. `tcp_send_payload`（socket 层）

状态不对（不是 `Established`/`CloseWait`）回 `E_OPNOTSUPP`；长度超 `TCP_PAYLOAD_MAX` 回 `E_INVAL`。

### 3. `tcp_accept`（socket 层）

从 `Listen` 槽上把已建立的连接**搬到新槽**，原槽退回 `Listen`（换一个新 ISS）。

## 决策

### 决策 1：分流判据用「有没有 tcp 状态」，不用 frame 里的 type

`frame` 里的东西来自用户态，**可伪造**。而「这个槽有没有 `ConnState`」是内核自己的记录。

### 决策 2：`accept` 没有 backlog 队列

真实 TCP 的 `accept` 从**已完成队列**里取一条（握手由内核完成，应用只取结果）。

这里没有队列：`Listen` 槽收到 SYN 进 `SynReceived`，收到 ACK 进 `Established`，
而 `accept` 把那个已建立的连接搬到新槽。

**代价：同一时刻一个 `Listen` 槽只能承载一条连接。** 对今天的用例够用；
真实服务端需要队列。已写进未决 1。

### 决策 3：`recv` 不需要改

因为 ADR-199 已经把 TCP 的载荷塞进了**同一个接收队列**。这条决策在 ADR-199 里就定了，
这一层直接受益 —— **`sys_sock_recv` 一行没动**。

## 判据八格（`t_tcp_syscall`）

```
tcpsys: send推进=true 无peer拒=true 超限拒=true accept空=true
        accept=true 重挂=true 新槽send=true dgram拒=true ⇒ true
```

## 一次「负样本没咬住」（本会话第七次同类错误）

**第一次负样本改的是 `sys_sock_send` 的分流**，但判据直接调 `socket::tcp_send_payload` ——
**判据验的东西和它声称覆盖的东西不是一回事**，负样本没红。

我试过让判据走真 syscall 路径（装 fd 再调 53 号），但那条路要 `current_proc()` + fd 表，
而用例跑在 boot 任务上没有进程上下文。

**最终做法**：判据验 `tcp_send_payload`（分流的**下游**），负样本也落在这一层（不推进 `snd_nxt`）。

这是**诚实的降级**：判据覆盖「段构造推进序号」，**不覆盖**「`sys_sock_send` 会不会走到这里」。
后者靠 `t_tcp_socket` 与代码审查。**我把它写出来，而不是假装覆盖了。**

## 负样本（正确的那个）

去掉 `tcp_send_payload` 里的 `snd_nxt` 推进：

```
tcpsys: send 没推进 snd_nxt 268435461->268435461
tcpsys: 新槽 send 不对
FAIL t_tcp_syscall
```

**两格同时红**（① 与 ⑦），都依赖同一个推进。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | **`PASS(33)`**，`tcpsys` 八格全绿 |

## TCP 现在的真实能力

| 能做 | 不能做 |
|---|---|
| `socket(SOCK_STREAM)` | 重传（丢一个段就永久卡住）|
| `listen` / `connect` | 滑动窗口（会淹没接收方）|
| `accept`（无 backlog）| 乱序重组 |
| `send`（真发 IPv4 帧）| TIME_WAIT 重发 ACK |
| `recv`（复用 UDP 队列）| 拥塞控制 |
| 握手与挥手 | **IPv6 的 TCP**（明确回 `E_OPNOTSUPP`）|

## 未决

1. **`accept` 的 backlog 队列**（现在一个 `Listen` 槽同时只能一条连接）
2. **重传**（没有定时器；丢一个段就永久卡住）
3. **滑动窗口**（字段照填，但不按对端窗口限制发送）
4. **乱序重组**
5. **IPv6 的 TCP**
6. **判据没覆盖 `sys_sock_send` 的分流本身**（见上面那节）
7. **拥塞控制**（明确不做）