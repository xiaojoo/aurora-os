# ADR-197：TCP 段格式与校验和

状态：**已采纳**（2026-11-22：`network/tcp.rs` 落地，`tcp` 八格全 true）

关联：ADR-181（socket 族）、ADR-196（驱动注册表）

> 切片 G 的**第一层**。**连接状态机还没做**，这一步只做「段的字节层」。

## 为什么分两层

UDP 的「帧」是一个完整的语义单位（一问一答）。TCP 的段不是：

| 层 | 内容 | 本 ADR |
|---|---|---|
| **字节层** | 段格式、校验和、`seq_len` | **做** |
| 状态机层 | LISTEN/SYN_SENT/ESTABLISHED/FIN_WAIT… | 未做 |
| 可靠性层 | 重传队列、滑动窗口、RTT 估计 | 未做 |
| 拥塞控制 | 慢启动、拥塞避免、快重传 | **明确不做** |

**先做字节层的理由**：它是唯一能被「纯函数判据」完整证伪的部分。状态机必须在真实网络上跑，
而那份工具链今天不存在。

## 交付

```rust
pub const TCP_HDR_MIN: usize = 20;
pub const TCP_HDR_MAX: usize = 60;
pub const TCP_PAYLOAD_MAX: usize = 1460;   // 1500 − 20(IP) − 20(TCP)

pub struct Segment<'a> { src_port, dst_port, seq, ack, flags, window, data_off, payload }

pub fn parse_segment(seg: &[u8]) -> Option<Segment<'_>>
pub fn build_segment(...) -> Option<usize>
pub fn tcp_checksum(src_ip, dst_ip, tcp_seg) -> u16
```

## 决策

### 决策 1：`seq_len()` 把 SYN/FIN 各算一个字节

**这是 TCP 最容易写错的地方之一。**

`SYN` 和 `FIN` 不携带数据，但它们**消耗序号**。漏了它们，握手与挥手的序号会差一格 ——
而那种错在「传数据」时**看不出来**（数据段本身是对的）。

```rust
pub fn seq_len(&self) -> u32 {
    let mut n = self.payload.len() as u32;
    if self.is_syn() { n += 1; }
    if self.is_fin() { n += 1; }
    n
}
```

### 决策 2：`parse_segment` 任何形状不对都回 `None`

不猜、不截短。头部长度必须 `20 <= hdr <= 60` **且 `hdr <= seg.len()`**。

### 决策 3：`build_segment` 不做「自动填窗口」

窗口是**连接状态**，不是段格式。调用方必须显式给 —— 便利函数会让「忘了更新窗口」
变成一种看不出来的 bug。

## 判据八格（`t_tcp_segment`）

```
tcp: 往返=true seq_len=true 校验和=true 发现翻转=true
     短头拒=true 长头拒=true 超长拒=true 载荷超限拒=true ⇒ true
```

## 一个实测撞出来的判据错法（值得记）

第一版校验和判据写的是「**填进去的值 == 重算的值**」，实测：

```
tcp: 校验和不对 填=0xf7a9 重算=0x0000
```

**重算是 0，不是 bug。** 因为重算时把**已经填好的校验和字段**也算进去了，
而按 RFC 1071 的定义，那种和**必然是 0** —— 这就是校验和的**自校验**性质。

正确判据：**`填的值 != 0 && 整段自校验 == 0`**。发现翻转那格也改成「翻转后自校验不再为 0」。

## 负样本（变异证红）

把 `seq_len` 里的 `SYN` 那支去掉：

```
tcp: seq_len 不对 syn=false fin=true syn+fin=false data=true
tcp: ... seq_len=false ⇒ false
```

**精准咬住。**（`fin` 与 `data` 两格仍是 true —— 说明判据是**分格**红的，不是整块红。）

## 读数

| 项 | 结果 |
|---|---|
| `check` | **20/20** |
| `handles` 档 | `tcp` 八格全绿，唯一失败是既有 `t_sdkdemo`（8.9%）|

## 一个门禁缺口（如实记）

`kernel/src/network/tcp.rs` 是**新增源文件**，但在我把它加进 `source_modules` 之前，
`check` **是绿的**。

**`check-module-interfaces` 只对账「登记了的模块」与源码，不检查「源码里有没有没登记的模块」。**
那条方向靠人自觉 —— 而这次是我自觉补的，不是门禁抓的。

已记为未决 1。

## 未决

1. **门禁缺口**：新增源文件未登记时 `check` 不报（`source_modules` 覆盖方向单一）
2. **连接状态机**（LISTEN/SYN_SENT/ESTABLISHED/…）
3. **重传与滑动窗口**
4. **`socket::create(SOCK_STREAM)`** 仍回 `E_NOSYS`
5. **拥塞控制**（明确不做）