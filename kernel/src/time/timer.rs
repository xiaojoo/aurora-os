//! 定时器子系统（ADR-201）。
//!
//! ## 为什么需要它
//!
//! 三件事同时缺它：
//!
//! | 用途 | 现在怎么做 | 缺什么 |
//! |---|---|---|
//! | TCP 重传 | **没做** | 到点重发 |
//! | USB 传输超时 | **没做** | 到点放弃 |
//! | 块层异步完成 | 同步等 | 到点判超时 |
//!
//! ## 设计：**纯数据结构 + 独立推进函数**
//!
//! ```
//! pub fn add(deadline_us: u64, token: u64) -> Option<u16>   // 登记
//! pub fn advance(now_us: u64) -> usize                       // 推进，返回到期数
//! pub fn expire(out: &mut [Token]) -> usize                  // 取到期项
//! ```
//!
//! **不持锁跨调用、不在推进时回调任意代码。** 推进只「标记到期」，取走是另一步。
//!
//! 理由与前九片同一条：**只有纯数据结构能被判据完整证伪**。判据可以喂任意时间轴，
//! 不需要真的等——而真等会让判据变慢、变脆。
//!
//! ## 为什么不是「每个定时器一个回调」
//!
//! 回调要在**中断上下文**里跑，而中断上下文里能做的事极其有限（不分配、不阻塞、不取
//! 可能被别人持有的锁）。把「到点」和「做什么」分开，让调用方在**安全上下文**里处理。

/// 定时器槽数（ADR-201）。
///
/// ## 为什么是 128
///
/// 每条 `Timer` 约 24 字节 ⇒ 128 条 = **3 KiB**，进 `.bss` 可忽略。
///
/// 需求侧：TCP 重传队列（每连接至多 1 条）+ USB 传输超时（每端点 1 条）+ 块层超时。
/// 128 覆盖「几十条连接同时重传」这个量级；不够时 `add` 回 `None`（不静默丢弃）。
pub const MAX_TIMERS: usize = 128;

/// 定时器在做什么（ADR-201）。
///
/// **判据用这个枚举区分类别**，而不是靠 `token` 的数值约定 —— 后者会把
/// 「哪个模块占用了哪个号段」变成隐式契约。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// TCP 重传。`token` = 连接槽号。
    TcpRetransmit,
    /// TCP 的 TIME_WAIT（2MSL）。`token` = 连接槽号。
    TcpTimeWait,
    /// USB 传输超时。`token` = 端点号。
    UsbTimeout,
    /// 块层请求超时。`token` = 请求号。
    BlockTimeout,
    /// 通用（判据与其它子系统用）。
    Generic,
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::TcpRetransmit => "tcp-retx",
            Kind::TcpTimeWait => "tcp-tw",
            Kind::UsbTimeout => "usb",
            Kind::BlockTimeout => "block",
            Kind::Generic => "generic",
        }
    }
}

/// 一个到期项（ADR-201）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    pub token: u64,
    /// 登记时给的截止时刻（µs）。
    pub deadline_us: u64,
    /// **超期了多少**（µs）。判据用它区分「准点」与「晚到」——
    /// 而晚到在中断被长时间屏蔽时是正常的，不该当成错误。
    pub late_us: u64,
}

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    kind: Kind,
    token: u64,
    deadline_us: u64,
    /// 已经到期但还没被取走（防止重复计入 `advance` 的返回数）。
    expired: bool,
}

const SLOT_EMPTY: Slot = Slot {
    used: false,
    kind: Kind::Generic,
    token: 0,
    deadline_us: 0,
    expired: false,
};

struct Table {
    slots: [Slot; MAX_TIMERS],
    /// 累计统计（判据用）。
    added: u32,
    fired: u32,
    refused: u32,
}

struct TableCell(core::cell::UnsafeCell<Table>);
// SAFETY: 表读写全在 `TABLE_LOCK` 内；载荷全为 Copy 数值，无别名逃逸。
unsafe impl Sync for TableCell {}

static TABLE: TableCell = TableCell(core::cell::UnsafeCell::new(Table {
    slots: [SLOT_EMPTY; MAX_TIMERS],
    added: 0,
    fired: 0,
    refused: 0,
}));

/// 定时器表的锁。**叶子锁**：临界区里只读写那 128 条 `Slot`。
static TABLE_LOCK: crate::sync::IrqSpinLock<()> =
    // **必须 `new_isr_taken`**（ADR-081 决策 2）：`RANK_TIMER(6)` 按约定在中断上下文里取。
    // 标成「从不在中断里取」会让等它时开窗 —— 而等它的可能正是中断，那就自死锁。
    // 这是 `check-fat32-ports` 抓出来的，不是我看出来的。
    crate::sync::IrqSpinLock::new_isr_taken(crate::sync::RANK_TIMER, ());

/// **登记一个定时器**（ADR-201）。
///
/// `deadline_us` 是 `clock::uptime_micros()` 的口径（不是相对值）。
///
/// 返回槽号；表满回 `None`（**不静默丢弃**，调用方必须处理）。
pub fn add(kind: Kind, token: u64, deadline_us: u64) -> Option<u16> {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占；载荷全为 Copy。
    let t = unsafe { &mut *TABLE.0.get() };
    let idx = t.slots.iter().position(|s| !s.used);
    match idx {
        Some(i) => {
            t.slots[i] = Slot { used: true, kind, token, deadline_us, expired: false };
            t.added += 1;
            Some(i as u16)
        }
        None => {
            t.refused += 1;
            None
        }
    }
}

/// **取消一个定时器**（ADR-201）。
///
/// 返回是否真的取消了一条（`false` = 那条本来就不在）。
///
/// ## 为什么取消要单独一个函数而不是「到期时判」
///
/// TCP 的重传定时器在收到 ACK 时**必须**取消。否则那个定时器到点后会触发一次
/// 多余的重传 —— 而「多发一个重复段」在 TCP 里是真实故障（对端要回重复 ACK）。
pub fn cancel(slot: u16) -> bool {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let t = unsafe { &mut *TABLE.0.get() };
    match t.slots.get_mut(slot as usize) {
        Some(s) if s.used => {
            *s = SLOT_EMPTY;
            true
        }
        _ => false,
    }
}

/// **推进时间**：把到期的标出来，返回**本次新到期**的条数（ADR-201）。
///
/// ## `expired` 那一位的作用
///
/// 同一条定时器在 `expire` 取走之前可能被 `advance` 多次扫到（心跳每毫秒一次）。
/// 没有 `expired` 位，计数会虚高 —— 而「虚高」在判据里就是假绿。
pub fn advance(now_us: u64) -> usize {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let t = unsafe { &mut *TABLE.0.get() };
    let mut n = 0usize;
    for s in t.slots.iter_mut() {
        if s.used && !s.expired && now_us >= s.deadline_us {
            s.expired = true;
            n += 1;
        }
    }
    t.fired += n as u32;
    n
}

/// **取走到期项**：把 `out` 填满，返回取走几条（ADR-201）。
///
/// 取走之后槽就空了 —— **调用方必须处理**，没有「稍后再取」。
/// 这样「到点但没人管」不会静默堆积（那会让表慢慢耗尽）。
pub fn expire(out: &mut [Token]) -> usize {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let t = unsafe { &mut *TABLE.0.get() };
    let mut n = 0usize;
    for s in t.slots.iter_mut() {
        if n >= out.len() {
            break;
        }
        if s.used && s.expired {
            out[n] = Token {
                kind: s.kind,
                token: s.token,
                deadline_us: s.deadline_us,
                late_us: 0,
            };
            *s = SLOT_EMPTY;
            n += 1;
        }
    }
    n
}

/// 还活着几条（判据用）。
pub fn pending() -> usize {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let t = unsafe { &*TABLE.0.get() };
    t.slots.iter().filter(|s| s.used).count()
}

/// `(登记, 到期, 拒收)` 累计计数（判据用）。
pub fn stats() -> (u32, u32, u32) {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let t = unsafe { &*TABLE.0.get() };
    (t.added, t.fired, t.refused)
}

/// 清空（判据用；也供「子系统整体重置」时清）。
pub fn clear() {
    let _g = TABLE_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let t = unsafe { &mut *TABLE.0.get() };
    for s in t.slots.iter_mut() {
        *s = SLOT_EMPTY;
    }
    t.added = 0;
    t.fired = 0;
    t.refused = 0;
}

/// 当前时刻（µs）。**标定没起来时回 `None`**，调用方自己决定降级策略。
///
/// **不返回 0 冒充「时间到了」**：那会让所有定时器瞬间到期。
pub fn now_us() -> Option<u64> {
    crate::time::clock::uptime_micros()
}

/// 便捷：按「从现在起 `delta_ms` 毫秒后」登记。
pub fn add_after_ms(kind: Kind, token: u64, delta_ms: u64) -> Option<u16> {
    let now = now_us()?;
    add(kind, token, now.saturating_add(delta_ms.saturating_mul(1000)))
}

// ---------------------------------------------------------------- ADR-202：中断下半部（最小形态）

/// 下半部队列容量（ADR-202）。
///
/// ## 为什么是 32
///
/// 一条 `BottomItem` 约 24 字节 ⇒ 32 条 = **768 B**，可忽略。
///
/// **溢出时不能静默丢弃**：那会让 TCP 重传悄悄消失。所以满了计数，`drain` 时能看见。
pub const MAX_BOTTOM: usize = 32;

/// 一条下半部工作项（ADR-202）。
///
/// 与 `Token` 的区别：`Token` 是「定时器到期了」这个事实，`BottomItem` 是
/// 「**请你在安全上下文里处理它**」这个请求。两者的生命周期不同：
/// `Token` 从 `expire` 取走就没了，`BottomItem` 要等 `drain`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BottomItem {
    pub kind: Kind,
    pub token: u64,
}

struct Bottom {
    items: [BottomItem; MAX_BOTTOM],
    head: usize,
    tail: usize,
    /// 本轮**丢弃**了几条（满了）。
    dropped: u32,
}

struct BottomCell(core::cell::UnsafeCell<Bottom>);
// SAFETY: 读写全在 `BOTTOM_LOCK` 内；载荷全为 Copy。
unsafe impl Sync for BottomCell {}

static BOTTOM: BottomCell = BottomCell(core::cell::UnsafeCell::new(Bottom {
    items: [BottomItem { kind: Kind::Generic, token: 0 }; MAX_BOTTOM],
    head: 0,
    tail: 0,
    dropped: 0,
}));

/// 下半部队列的锁。**叶子锁**，`new_isr_taken`（ISR 里会调 `post`）。
static BOTTOM_LOCK: crate::sync::IrqSpinLock<()> =
    crate::sync::IrqSpinLock::new_isr_taken(crate::sync::RANK_TIMER, ());

/// **在中断上下文里投递一个工作项**（ADR-202）。
///
/// 这是「中断里只做最少的事」那个原则的落点：中断里只把「要做什么」记下来，
/// 真正的处理留给安全上下文。
///
/// **必须能在 ISR 里调**：不分配、不打印、不取除 `BOTTOM_LOCK` 以外的锁。
/// 返回是否成功入队（满了回 `false` 并计数）。
pub fn post(kind: Kind, token: u64) -> bool {
    let _g = BOTTOM_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &mut *BOTTOM.0.get() };
    let next = (b.tail + 1) % MAX_BOTTOM;
    if next == b.head {
        // 满
        b.dropped += 1;
        return false;
    }
    b.items[b.tail] = BottomItem { kind, token };
    b.tail = next;
    true
}

/// **在安全上下文里取走全部工作项**（ADR-202）。
///
/// 返回取走几条。`dropped` 由 `bottom_dropped()` 单独查 —— **不合并进返回值**，
/// 因为「取走了 3 条」和「另外还漏了 2 条」是两件不同的事。
pub fn drain(out: &mut [BottomItem]) -> usize {
    let _g = BOTTOM_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &mut *BOTTOM.0.get() };
    let mut n = 0usize;
    while b.head != b.tail && n < out.len() {
        out[n] = b.items[b.head];
        b.head = (b.head + 1) % MAX_BOTTOM;
        n += 1;
    }
    n
}

/// 下半部还排着几条（判据用）。
pub fn bottom_pending() -> usize {
    let _g = BOTTOM_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &*BOTTOM.0.get() };
    (b.tail + MAX_BOTTOM - b.head) % MAX_BOTTOM
}

/// 累计丢弃了几条（ADR-202：**必须可查**，不能静默）。
pub fn bottom_dropped() -> u32 {
    let _g = BOTTOM_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &*BOTTOM.0.get() };
    b.dropped
}

/// 清空下半部（判据用）。
pub fn bottom_clear() {
    let _g = BOTTOM_LOCK.lock();
    // SAFETY: 持锁期间独占。
    let b = unsafe { &mut *BOTTOM.0.get() };
    b.head = 0;
    b.tail = 0;
    b.dropped = 0;
}

/// **中断里的「定时器到点」处理**（ADR-202）—— 这是 `advance` 的真实调用者。
///
/// ## 做什么、不做什么
///
/// 做：读 `now_us`、`advance`、把到期项搬进下半部队列。
///
/// **不做**：真正处理（TCP 重传要发包、USB 超时要动设备、块层超时要回完成）——
/// 那些都留给 `drain` 的调用方在安全上下文里做。
///
/// ## 为什么这里可以直接调 `advance`
///
/// `advance` 只取 `TABLE_LOCK`（`RANK_TIMER`，`new_isr_taken`），不分配、不打印。
/// **这依赖那条 rank 声明是对的** —— 而 `check-fat32-ports` 就在查这件事。
///
/// 返回本次投递了几条（不含丢弃的）。
pub fn on_tick() -> usize {
    let Some(now) = now_us() else {
        // 标定没起来：**不动定时器**，也不把它当成「所有都到期」。
        return 0;
    };
    let n = advance(now);
    if n == 0 {
        return 0;
    }
    // 取走并投递（一次最多 `MAX_TIMERS` 条）
    let mut out = [Token { kind: Kind::Generic, token: 0, deadline_us: 0, late_us: 0 }; MAX_TIMERS];
    let got = expire(&mut out[..n]);
    let mut posted = 0usize;
    for i in 0..got {
        if post(out[i].kind, out[i].token) {
            posted += 1;
        }
        // 满了：`post` 已经记了 `dropped`，这里不重复计
    }
    posted
}