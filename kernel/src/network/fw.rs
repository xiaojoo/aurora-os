//! ADR-267：最小防火墙的内核侧——规则存储、挂载点判决、加载/控制入口。**未编译、未运行。**
//!
//! 第一期 = **UDP/NDP 入站无状态过滤**。唯一挂载点是 `socket::deliver_frame`（由 `poll_once`
//! 在 syscall 上下文调用，不在中断里）：
//!
//! * UDP（v4/v6）：拿**内核解析器已解出**的端点构造 [`host_fw::Packet`]，在 `enqueue` 之前判；
//! * NDP 分支（`next header = 58`）：用 `host_fw::parse::parse_eth` 取头，在判属/`handle_frame`/回 NA 之前判。
//!
//! 字节码、验证器、执行器、解析全在 `crates/host-fw`（no_std、无 unsafe），与宿主机测试共用同一份源码。
//!
//! ## 锁（lock-order.md 新增一行 `RANK_FW = 42`）
//!
//! 一把 `IrqSpinLock<FwState>`，**叶子**：临界区里只做①执行已验证字节码（≤128 步，纯计算）
//! ②读写这张定长状态。不取任何别的锁、不分配、不打日志、不 yield。
//! 计数器是锁外的 `AtomicU64`（只读数，不参与同步决策，Relaxed）。
//!
//! 取锁点与调用上下文（逐一核过）：
//! * [`filter`] / [`filter_icmp6_frame`]：`deliver_frame` 内，调用时不持锁（`poll_once` 的调用方
//!   `sys_sock_recv` 在 `user.rs:3341` 调它时已放掉 HANDLE；`enqueue` 取 NET(36) 在我们放锁之后）。
//! * [`load`] / [`clear`] / [`enable`] / [`disable`] / [`stats_record`]：81/82 号，`copy_from_user`
//!   （内部取 VMM 20）、`current_cred`（内部取 RUNQ 8）**都在取本锁之前完成**。
//!
//! 42 比 NET(36)/LEDGER(40)/RAND(41) 都深：将来即便有人在持 NET 的路径里调 `filter`，严格递增仍成立。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use host_fw::parse::{parse_eth, Parsed};
use host_fw::{Dir, Packet, Program, Verdict, VerifyError};

use crate::sync::{IrqSpinLock, RANK_FW};

/// 单个规则程序的指令数上限（容量，登记在 capacity-baseline.toml）。与 `host_fw::MAX_INSNS` 逐字一致。
pub const MAX_FW_INSNS: usize = 128;
const _: () = assert!(MAX_FW_INSNS == host_fw::MAX_INSNS);

/// 81 号单次拷贝的字节上限（= 128 × 8）。
pub const FW_PROG_BYTES_MAX: usize = host_fw::MAX_PROG_BYTES;
/// 81 号 `rdx` 的唯一合法标志位：装载成功后立即启用。
pub const FW_LOAD_ENABLE: u64 = 1;

/// 82 号子命令（`rdi`）。
pub const FW_CTL_CLEAR: u64 = 0;
/// 82 号子命令：启用（无程序 ⇒ `E_NOT_FOUND`）。
pub const FW_CTL_ENABLE: u64 = 1;
/// 82 号子命令：停用（程序保留）。
pub const FW_CTL_DISABLE: u64 = 2;
/// 82 号子命令：读 64 字节统计记录到 `rsi`（`rdx` 必须等于 [`FW_STATS_LEN`]）。
pub const FW_CTL_STATS: u64 = 3;

/// 统计记录长度。
pub const FW_STATS_LEN: usize = 64;
/// 统计记录魔数（小端字节 `46 57 53 31` = "FWS1"）。
pub const FW_STATS_MAGIC: u32 = 0x3153_5746;

struct FwState {
    /// 只放**验证成功**的程序（`Program` 的唯一构造路径就是 `host_fw::verify*`）。
    prog: Option<Program>,
    /// 启用开关。**初值 false**：默认放行（ADR-267 §3.3）。
    enabled: bool,
    /// 每次成功装载 +1（0 = 从未装载；回绕跳过 0）。
    generation: u32,
}

static FW: IrqSpinLock<FwState> = IrqSpinLock::new(RANK_FW, FwState { prog: None, enabled: false, generation: 0 });

static EVALUATED: AtomicU64 = AtomicU64::new(0);
static ACCEPTED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);
static MALFORMED_DROPPED: AtomicU64 = AtomicU64::new(0);
static LOADS_REJECTED: AtomicU64 = AtomicU64::new(0);
static LAST_REJECT: AtomicU32 = AtomicU32::new(0);

/// 挂载点判决。`true` = 放行（继续投递），`false` = 丢弃。
///
/// 未启用或无程序 ⇒ 放行且**不计 evaluated**（ktest 的防空转证人靠这一点区分"判过放行"与"没判"）。
/// 执行异常（已验证程序不该出现）⇒ 计 `FAULTS` 并**放行**（与默认策略一致；R21 待裁决）。
pub fn filter(pkt: &Packet) -> bool {
    let mut g = FW.lock();
    let st = g.get();
    if !st.enabled {
        return true;
    }
    let Some(p) = st.prog.as_ref() else { return true };
    EVALUATED.fetch_add(1, Ordering::Relaxed);
    match host_fw::run(p, pkt) {
        Ok(o) => match o.verdict {
            Verdict::Accept => {
                ACCEPTED.fetch_add(1, Ordering::Relaxed);
                true
            }
            Verdict::Drop => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
                false
            }
        },
        Err(_) => {
            FAULTS.fetch_add(1, Ordering::Relaxed);
            true
        }
    }
}

fn active() -> bool {
    let mut g = FW.lock();
    let st = g.get();
    st.enabled && st.prog.is_some()
}

/// NDP 分支的判决。取不出 ICMPv6 头 ⇒ 过滤器启用时**丢弃**（计 `MALFORMED_DROPPED`），未启用时放行。
///
/// 为什么可以丢：`parse_eth` 的 ICMPv6 接受集严格宽于 `ndp::parse_nd`（宿主机差分 0 例外），
/// 取不出头的帧 `handle_frame` 本来也不会处理——丢它不改变 NDP 行为，只是不让它走到判属那一步。
pub fn filter_icmp6_frame(f: &[u8]) -> bool {
    match parse_eth(f, Dir::In) {
        Parsed::Packet(p) => filter(&p),
        _ => {
            if active() {
                MALFORMED_DROPPED.fetch_add(1, Ordering::Relaxed);
                false
            } else {
                true
            }
        }
    }
}

/// 验证并装载一份字节码。**验证在锁外、对内核副本做**；失败 ⇒ 现有程序/开关/世代号一律不动。
/// 成功返回新世代号（≥1）。
pub fn load(bytes: &[u8], enable: bool) -> Result<u32, VerifyError> {
    let mut staged = Program::blank();
    if let Err(e) = host_fw::verify_into(bytes, &mut staged) {
        LOADS_REJECTED.fetch_add(1, Ordering::Relaxed);
        LAST_REJECT.store(e.code(), Ordering::Relaxed);
        return Err(e);
    }
    let mut g = FW.lock();
    let st = g.get();
    st.prog = Some(staged);
    let next = st.generation.wrapping_add(1);
    st.generation = if next == 0 { 1 } else { next };
    if enable {
        st.enabled = true;
    }
    Ok(st.generation)
}

/// 清空：撤程序并停用（回到默认放行）。
pub fn clear() {
    let mut g = FW.lock();
    let st = g.get();
    st.prog = None;
    st.enabled = false;
}

/// 启用。无程序 ⇒ `false`（不改状态）。
pub fn enable() -> bool {
    let mut g = FW.lock();
    let st = g.get();
    if st.prog.is_none() {
        return false;
    }
    st.enabled = true;
    true
}

/// 停用（程序保留，可再启用）。
pub fn disable() {
    let mut g = FW.lock();
    g.get().enabled = false;
}

/// 计数快照（ktest 用；与 [`stats_record`] 同源）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FwStats {
    /// 当前世代号。
    pub generation: u32,
    /// 当前程序指令数（无程序 = 0）。
    pub insns: u16,
    /// 是否启用。
    pub enabled: bool,
    /// 判过的包数。
    pub evaluated: u64,
    /// 判放行。
    pub accepted: u64,
    /// 判丢弃。
    pub dropped: u64,
    /// 执行异常次数。
    pub faults: u64,
    /// NDP 分支取不出头而丢弃的帧数。
    pub malformed_dropped: u64,
    /// 被验证器拒绝的装载次数。
    pub loads_rejected: u64,
    /// 最近一次拒绝的 `VerifyError::code()`（0 = 从未）。
    pub last_reject: u32,
}

/// 取快照。锁内只读三格，计数器在锁外读。
pub fn stats() -> FwStats {
    let (generation, insns, enabled) = {
        let mut g = FW.lock();
        let st = g.get();
        let n = st.prog.as_ref().map(|p| p.len()).unwrap_or(0);
        (st.generation, u16::try_from(n).unwrap_or(u16::MAX), st.enabled)
    };
    FwStats {
        generation,
        insns,
        enabled,
        evaluated: EVALUATED.load(Ordering::Relaxed),
        accepted: ACCEPTED.load(Ordering::Relaxed),
        dropped: DROPPED.load(Ordering::Relaxed),
        faults: FAULTS.load(Ordering::Relaxed),
        malformed_dropped: MALFORMED_DROPPED.load(Ordering::Relaxed),
        loads_rejected: LOADS_REJECTED.load(Ordering::Relaxed),
        last_reject: LAST_REJECT.load(Ordering::Relaxed),
    }
}

/// 82 号 STATS 的 64 字节记录（小端）：
///
/// ```text
///  0..4  magic "FWS1"    4..8  generation    8..10 insns   10 enabled   11 保留(0)
/// 12..16 last_reject    16..24 evaluated    24..32 accepted   32..40 dropped
/// 40..48 faults         48..56 malformed_dropped              56..64 loads_rejected
/// ```
pub fn stats_record() -> [u8; FW_STATS_LEN] {
    let s = stats();
    let mut b = [0u8; FW_STATS_LEN];
    put(&mut b, 0, &FW_STATS_MAGIC.to_le_bytes());
    put(&mut b, 4, &s.generation.to_le_bytes());
    put(&mut b, 8, &s.insns.to_le_bytes());
    put(&mut b, 10, &[u8::from(s.enabled)]);
    put(&mut b, 12, &s.last_reject.to_le_bytes());
    put(&mut b, 16, &s.evaluated.to_le_bytes());
    put(&mut b, 24, &s.accepted.to_le_bytes());
    put(&mut b, 32, &s.dropped.to_le_bytes());
    put(&mut b, 40, &s.faults.to_le_bytes());
    put(&mut b, 48, &s.malformed_dropped.to_le_bytes());
    put(&mut b, 56, &s.loads_rejected.to_le_bytes());
    b
}

fn put(b: &mut [u8; FW_STATS_LEN], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}
