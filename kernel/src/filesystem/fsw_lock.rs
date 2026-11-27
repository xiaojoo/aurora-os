//! ADR-265：可写卷的**卷级写互斥**（"FSW 锁"）。
//!
//! 整个模块受 `#[cfg(all(feature = "handles", feature = "fs-open", feature = "fs-rw"))]` 门控
//! （在 `filesystem/mod.rs` 的 `mod` 声明处加），因为 `sched::current_identity` 只在 `handles` 下存在。
//!
//! ## 为什么需要它（有证据）
//! 并发追加的丢数据根源是 `读 size → 写数据 → 写 size` 之间 size 被别人改了。
//! 沙箱穷举（2 个写者，16172 个"两者都完成"的交错）：不加锁 **12210 个丢数据/覆盖（75.5%）**，加锁后 **0**。
//! 乐观 CAS（提交前复核 size）**救不了**：数据区在复核之前已被覆盖（同一穷举里仍有 30708 个损坏交错）。
//! 所以必须互斥，且互斥区必须覆盖"定位目录项 → 读 size → 写数据 → 改 size"整段。
//! `>`（unlink+create+append）还必须**整体**持锁：细粒度下 218 个交错里 57 个（26%）让并发追加者观察到"文件不存在"。
//!
//! ## 为什么**不是** `IrqSpinLock` / `OpenSpinLock`
//! * 临界区含毫秒级磁盘 IO。`IrqSpinLock::lock()` 持锁 IF=0，AHCI 同步读要等完成中断，只能走轮询宽限窗；
//!   且 `LOCK_WATCHDOG_CYCLES≈60ms` 到期即 L4。
//! * `OpenSpinLock` 保持 IF，但 `OPEN_DEPTH≠0` 时 `preempt_point` 不换出（ADR-255），等待者纯自旋。
//!   量级估算（**IO 耗时是假设，未实测**）：等待者每次追加烧 1~100 ms CPU。
//! * ADR-248：AHCI 入口**拒绝任何外层 rank≥4 的调用**。FSW 若是 `IrqSpinLock` 且 rank≥4，持锁进 AHCI 会被 `Denied`；
//!   若 rank<4，则要占 1..9 里仅剩的 2/3/7/9 之一并改 `lock-order.md` 与 `name()`。
//!
//! ## 本锁是什么
//! 一个 `AtomicBool`（"卷忙"位）+ **让出 CPU 的退避重试**。它**不是** `sync` 的 lockdep 锁：不进 `INNERMOST` 栈、
//! 不占 rank，所以持有者可以调 AHCI（4）、块层（37）、dentry/inode（38）。**代价（如实记）**：lockdep 看不见它，
//! 若有人在持 `IrqSpinLock` 时调 `lock()`（会让出 = 持自旋锁换人），**没有机制当场报错**——只能靠本模块的调用点约束：
//! 只在 syscall 入口调用，调用时不持任何内核锁。`ktest` 里加一格"持 TEST 锁调 lock() 必须被 `debug_assert` 拒"。
//!
//! 取不到时 `sched::yield_now()`：它用 `int 0xF0` 自陷（sched/mod.rs:1407），**关着窗口也能让出**，
//! 是 `t_waitqueue`（ktests/sched/sched.rs:983）已使用的原语。
//!
//! **不用 `WaitQueue::wait_while` 的理由**：产品代码里没有"在用户 syscall 内按 qid 睡眠"的先例（`sync::wait_queue(`
//! 只被 ktests 调用；`wait_on_proc` 走 `sched::wait_for_proc`），其前置条件在 syscall 上下文是否成立**未证实**。
//! 退避重试最坏是"礼貌的自旋"（每轮让出），不是烧满时间片，也不会死锁。若日后证实可用，把 `lock()` 里的
//! `yield_now` 换成睡眠，**协议其余部分不变**（沙箱穷举 74 状态：互斥 0 违例、死锁 0；去掉唤醒的变异 → 9 个死锁终态）。
//!
//! ## 被杀（如实记，未完全解决）
//! 持有者在临界区内被 `terminate_task` 终止：内核栈上的 `FswGuard` **不会**被展开（panic=abort，ADR-005），
//! 锁会永久泄漏。缓解：`OWNER` 记 `(gidx,id)`；`lock()` 每 `REAP_CHECK_EVERY` 轮检查持有者。
//! `terminate_task` 会先把仍在本 CPU 运行的任务标成 `Free`，所以“非 live”还必须再过“当前不在任何 CPU 上”一关；
//! 否则旁观者会在旧持有者仍写盘时误接管。确认离 CPU 后才转移 `OWNER` 并计数 `FSW_ORPHANED`。
//! `Drop` 只释放自己这一代 `OWNER`，旧守卫即使异常执行也不能放掉新持有者的锁。
//! **接管后卷可能处于半写状态**：好在追加协议规定"size 最后改"，半写最坏是泄漏簇/链长于 size，不会读到未写数据
//! （沙箱位级崩溃模型逐写点 0 违例）。QEMU 正向已跑；孤儿接管竞态未做专用负样本。
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// "卷忙"位。`true` = 有人在写。
static BUSY: AtomicBool = AtomicBool::new(false);
/// 持有者身份 `(gidx << 32) | id`；`NO_OWNER` = 无。只用于孤儿检测与诊断，**不参与互斥判定**。
/// 打包进一个 `AtomicU64` 是为了单次原子读写：两个原子量之间会被撕裂（读到新 gidx 配旧 id）。
static OWNER: AtomicU64 = AtomicU64::new(NO_OWNER);
const NO_OWNER: u64 = u64::MAX;

/// 统计（判据用：没有这些数，"锁验证过了"只是空话）。
pub static FSW_ACQUIRES: AtomicU32 = AtomicU32::new(0);
pub static FSW_CONTENDED: AtomicU32 = AtomicU32::new(0);
pub static FSW_YIELDS: AtomicU32 = AtomicU32::new(0);
pub static FSW_ORPHANED: AtomicU32 = AtomicU32::new(0);
pub static FSW_GAVE_UP: AtomicU32 = AtomicU32::new(0);

/// 每多少次让出检查一次持有者是否已死。
const REAP_CHECK_EVERY: u32 = 64;
/// 让出次数上限：超过则放弃返回 `None`（调用方回 `E_EXHAUSTED`，**不无限等**）。
/// **20_000 是占位，需实测定标**：沙箱轮转模型里 16 个竞争者×30 步临界区单线程最多让出 90 次，
/// 真机 IO 毫秒级、tick 间隔未知，所以这个数无法在沙箱里定。
pub const MAX_YIELDS: u32 = 20_000;

#[inline]
fn pack(gidx: usize, id: u32) -> u64 {
    ((gidx as u64) << 32) | id as u64
}

/// 持有卷写锁的凭证。`Drop` 放锁（含 `?` 提前返回）。
#[must_use = "丢弃守卫会立即放锁，等于什么都没锁"]
pub struct FswGuard {
    owner: u64,
}

/// 尝试取卷写锁。成功返回守卫；让出 `MAX_YIELDS` 次仍取不到返回 `None`。
///
/// **调用约束**：不得持有任何 `IrqSpinLock`/`OpenSpinLock`（含 `RANK_HANDLE`）——本函数会让出 CPU。
/// 无任务身份（boot 任务/ISR）返回 `None`：这条锁只服务用户 syscall。
pub fn lock() -> Option<FswGuard> {
    let (gidx, id) = crate::sched::current_identity()?;
    let me = pack(gidx, id);
    FSW_ACQUIRES.fetch_add(1, Ordering::Relaxed);
    let mut spins = 0u32;
    let mut counted = false;
    loop {
        if BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            OWNER.store(me, Ordering::Relaxed);
            return Some(FswGuard { owner: me });
        }
        if !counted {
            FSW_CONTENDED.fetch_add(1, Ordering::Relaxed);
            counted = true;
        }
        spins += 1;
        if spins > MAX_YIELDS {
            FSW_GAVE_UP.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if spins % REAP_CHECK_EVERY == 0 {
            let o = OWNER.load(Ordering::Relaxed);
            if o != NO_OWNER {
                let (og, oi) = ((o >> 32) as usize, o as u32);
                if !crate::sched::thread_live(og, oi) && !owner_still_running(og, oi) {
                    // 持有者已死：接管。BUSY 一直为 true，只转移 OWNER；CAS 失败说明别人先接管了。
                    if OWNER.compare_exchange(o, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                        FSW_ORPHANED.fetch_add(1, Ordering::Relaxed);
                        return Some(FswGuard { owner: me });
                    }
                }
            }
        }
        FSW_YIELDS.fetch_add(1, Ordering::Relaxed);
        crate::sched::yield_now();
    }
}

impl Drop for FswGuard {
    fn drop(&mut self) {
        // 只有当前世代的持有者能放锁。孤儿接管后旧守卫若被异常执行，也不能释放新持有者的锁。
        if OWNER
            .compare_exchange(self.owner, NO_OWNER, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            BUSY.store(false, Ordering::Release);
        }
    }
}

fn owner_still_running(gidx: usize, id: u32) -> bool {
    (0..crate::arch::x86_64::cpu::MAX_CPUS).any(|cpu| {
        crate::sched::current_of(cpu) == gidx && crate::sched::id_of(gidx) == id
    })
}

/// 判据用：当前是否有人持锁。
pub fn is_busy() -> bool {
    BUSY.load(Ordering::Acquire)
}
