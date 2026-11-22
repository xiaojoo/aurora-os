# ADR-199：TCP 接进 socket 层

状态：**已采纳**（2026-11-22：`SOCK_STREAM` 可用，`tcpsock` 七格全 true）

关联：ADR-197（段格式）、ADR-198（状态机）、ADR-181（socket 族，它当时回 `E_NOSYS`）

> 切片 G 的**第三层**。ADR-197/198 做出了段格式与状态机，但 `socket(SOCK_STREAM)` 仍回
> `E_NOSYS` —— **用户态还用不了**。这一层把它接进 socket 槽。

## 交付

```rust
pub struct SocketTcp(UnsafeCell<Option<ConnState>>);   // Socket 槽里新增一格

pub fn tcp_info(slot, gen) -> Option<TcpInfo>
pub fn tcp_listen(slot, gen) -> Result<(), u64>
pub fn tcp_start_connect(slot, gen) -> Result<Reply, u64>
pub fn tcp_on_segment(slot, gen, seg, src) -> Result<Option<Reply>, u64>
pub fn tcp_close(slot, gen) -> Result<Option<Reply>, u64>
```

`create(AF_INET, SOCK_STREAM)` 现在**成功**，初始 `Listen` 态。

## 决策

### 决策 1：`ConnState` 放进 socket 槽，不做独立的连接表

理由：连接的**身份**就是 socket 槽（`(slot, gen)` 已经是稳定身份）。
再建一张连接表就要维护两张表的同步，而那份同步没有额外的语义价值。

### 决策 2：`SocketTcp` 用 `UnsafeCell` 包一层

`Socket` 存在 `IrqSpinLock<SocketTable>` 里，而 `ConnState` 要**可变**（`on_segment` 收 `&mut`）。

表锁已经保证互斥，所以这里只需要绕过 `&self`。三处 `unsafe` 全在 `TABLE`（`RANK_NET=36`）内，
`ConnState` 是纯 `Copy` 数值。

### 决策 3：**TCP 的数据复用 UDP 的接收队列**

这是本 ADR 最关键的一个接线决定。

```rust
// tcp_on_segment 里：
if accepted {
    let _ = enqueue(slot_port(slot), src, &payload[..payload_len]);
}
```

**理由**：接收队列的语义（环形、有界、按端口投递）与传输层无关。
用户态的 `recv` 也走同一个出口 —— 不必为 TCP 再写一条读取路径。

**一个实测撞出来的坑**：`enqueue` 按**本地端口**投递，端口 0 的 socket 收不到。
所以 `tcp_on_segment` 必须先 `bind` 才能收到数据。判据第一版没 `bind`，
`数据入队=false` —— 那是**测试的错**。

### 决策 4：`tcp_*` 函数返回「要发的段」而不是自己发

与 `udp` 同一纪律：**socket 层不碰设备**。调用方（syscall 层）拿到段去发。

这样判据可以只测状态机与段构造，不需要网卡。

## 判据七格（`t_tcp_socket`）

```
tcpsock: create=true dgram无tcp=true listen=true 连接=true
         握手=true 数据入队=true 关闭=true ⇒ true
```

## 一个必须跟着改的旧判据

`t_socket_family` 里有一条「`SOCK_STREAM` 必须回 `-38`」—— 那是 TCP 状态机还不存在时写的。

`create` 放行之后它立刻变红。**这与 AF_INET6 那条是同一个教训**：

> **实现之后判据必须跟着实现走，否则功能上线时那条用例反而变红。**

改成「能建且初始是 `Listen`」之后恢复。

## 负样本（变异证红）

把 `create` 的类型检查改回只收 `SOCK_DGRAM`：

```
tcpsock: create(STREAM) 失败 0xffffffffffffffff
```

**`t_tcp_socket` 与 `t_socket_family` 同时红** —— 两条判据都在看同一件事，这是对的。

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | `tcpsock` 与 `sock` 全绿 |

## TCP 现在的真实能力

| 能做 | 不能做 |
|---|---|
| `socket(SOCK_STREAM)` | 重传（丢一个段就永久卡住）|
| `listen` / 主动连接 | 滑动窗口（会淹没接收方）|
| 段级握手与挥手 | 乱序重组 |
| 数据收发（经 UDP 队列）| TIME_WAIT 重发 ACK |
| 对错 ACK、乱序的拒绝 | 拥塞控制 |

## 未决

1. **重传**（没有定时器）
2. **滑动窗口**
3. **乱序重组**
4. **`sys_sock_send`/`recv` 的 TCP 分支**（今天它们仍按 UDP 的 `UDP_PAYLOAD_MAX` 限长，
   且 `send` 走 `udp::build_frame` —— **TCP 的 syscall 路径还没接**）
5. **`accept`**（今天在 DGRAM 上回 `-95`，在 STREAM 上还没实现）
6. **拥塞控制**（明确不做）