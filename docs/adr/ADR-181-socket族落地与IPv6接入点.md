# ADR-181：socket 族落地（48–55）与 IPv6 的接入点

状态：**部分采纳**（2026-11-22：48/49/51/53/54/55 已落地；50/52 回 -95；TCP 与 IPv6 见未决）

关联：ADR-180（per-process fd 表）、ADR-165（网络两族语义不合并）、ADR-176（声明的号必有臂）

> 写作纪律：每条结论标「实测」或「推断」。

## 背景

### 现状（实测）

| 项 | 现状 |
|---|---|
| 48–55 号 | **已声明、已占位，但全是 `nosys()` 空壳** |
| 网络栈 | 只有**原始以太网帧**（33/34）+ DHCP/DNS/ARP，**没有 UDP、没有 TCP** |
| fd 表 | 已有（ADR-180），但**没有 fd 号段**接入 |
| IPv6 | **零**（`dns.rs` 只有 `DNS_QTYPE_A`） |

### 号段已被占，这是好事

`check-syscall-abi-arms` 判据 3 要求「声明的号必有臂」，所以 48–55 现在挂着 `nosys()`。
**这 8 个号的位置是对的**（48–55 连号、在 47 `DNS_RESOLVE` 之后），不需要重新分配。

## 决策

### 决策 1：先做 UDP，不做 TCP

`socket()` 的 `type` 参数允许 `SOCK_DGRAM`/`SOCK_STREAM`。**本轮只实现 `SOCK_DGRAM`**：

| 理由 | 说明 |
|---|---|
| UDP 无需状态机 | 发就是打包发、收就是取队列；TCP 要三次握手/重传/拥塞控制 |
| DNS 已经要它 | `dns.rs` 今天自己拼 UDP 包，走 socket 后可以复用 |
| IPv6 可复用 | UDP over IPv6 只多一个伪首部校验，TCP over IPv6 要改整个状态机 |

**`SOCK_STREAM` 显式回 `-38`（ENOSYS）并记日志点名**——不静默降级成 DGRAM。

### 决策 2：`domain` 参数今天就收 `AF_INET` 与 `AF_INET6`

即使 IPv6 还没实现，**参数形状现在就要对**：

```c
int socket(int domain, int type, int protocol);
//         ^^^^^^ 现在就收 2 (AF_INET) 与 10 (AF_INET6)
```

`AF_INET6` 今天回 `-38`，但**不是形状错误**（`-22`），而是「这个族还没实现」。
这个区分很重要：调用方要能分辨「我参数写错了」与「内核还不支持」。

### 决策 3：socket 返回 fd，不是句柄

这是 ADR-180 的用途所在：

    48 socket() -> fd（3 起，0/1/2 是标准流）
    49 bind(fd, addr, len)
    51 connect(fd, addr, len)   // UDP 的 connect = 设默认对端
    53 send(fd, buf, len, flags)
    54 recv(fd, buf, len, flags)
    55 close(fd)                 // 等价于 fd 版 close

**50 `listen` / 52 `accept` 对 DGRAM 无意义**，回 `-95`（EOPNOTSUPP）并记日志。

### 决策 4：地址结构用 Linux 的 `sockaddr_in` 布局

```c
struct sockaddr_in {
    sa_family_t    sin_family;  // u16, 2
    in_port_t      sin_port;    // u16, 网络序
    struct in_addr sin_addr;    // u32, 网络序
    char           sin_zero[8]; // 填充
};
```

**必须字节级一致**，否则用户态 `bind()` 传进来的 16 字节读错位。
IPv6 用 `sockaddr_in6`（28 字节），`sin6_family` 同为 u16。

### 决策 5：socket 对象挂在 fd 表后面，用句柄包装

    用户 fd ──→ 句柄（capability 表）──→ ObjRef::Socket { slot, gen } ──→ socket 表

**为什么中间还要一层句柄**：`close` 的语义、权限位、跨进程传递（`dup`/`SCM_RIGHTS`）
都已经在句柄层做好了。socket 直接放 fd 表里等于把这三件事重做一遍。

## 本轮范围

| 号 | 本轮 | 说明 |
|---|---|---|
| 48 `socket` | **实现** | `AF_INET` + `SOCK_DGRAM` 可用 |
| 49 `bind` | **实现** | |
| 50 `listen` | 回 `-95` | DGRAM 无意义 |
| 51 `connect` | **实现** | UDP 设默认对端 |
| 52 `accept` | 回 `-95` | DGRAM 无意义 |
| 53 `send` | **实现** | |
| 54 `recv` | **实现** | 非阻塞，空队列回 `-11` |
| 55 `close` | **实现** | |

## 未决

1. **TCP**（`SOCK_STREAM`）—— 需要状态机，单独 ADR。
2. **IPv6**（`AF_INET6`）—— 需要地址类型、NDP、SLAAC、AAAA 记录，单独 ADR。
3. **`sendto`/`recvfrom` 的地址参数**（无 `connect` 时怎么给对端）—— 本轮只做 `connect` 后的 send/recv。
4. **socket 表的容量**与回收时机。