//! §9.4 / §9.7 / ADR-011-临时 的共同地基：一块**跨重启保留**的记录区。
//!
//! 位置不在文件系统里，也不在 ESP 卷内 —— 它在 GPT 说"未分配"的那段空隙里
//! （ESP 卷尾与备份 GPT 阵列之间）。为什么不先加第二条 GPT 分区项：那会改动分区表
//! 的 CRC 并让引导加载器第一次面对两个分区，而今天的验收不依赖它。这条取舍记在
//! BACKLOG（真机上要变成带 GUID 的分区）。
//!
//! 形状的三条硬规矩各有判据，都来自手册 §9.4 的 011-临时那段：
//! 1. **读不到就按最坏情况处理**：`read()` 的 `Err` 就是最坏情况，绝不"当 0 看"。
//! 2. **一次写一半必须能被判为读不到**，而不是读出一个看似合法的中间值 ⇒
//!    `size` 是首字段，`magic`/`version`/`kind` 紧随，校验和覆盖"头部 + payload"全体。
//!    从盘上读来的 `size` 也要先验上界（它会指着缓冲外面）。
//! 3. **多槽 + 全局单调的 `seq`** ⇒ 每个种类各取自己 `seq` 最大的那条；被校验和挡掉的那条不参与比较。
//!    `seq` 是**整块区**的计数而不是每个种类自己的：两种记录（`KIND_BOOT`/`KIND_CRASH`）各数各的，
//!    "谁最新"就没有定义，而写下一个槽的位置也由它决定。
//!
//! 这里**只装可靠性判定用的数**。任何"防篡改证据"用法都要在评审时被驳回：这段存储
//! 任何本地代码都能改，验签是 011-正式（M6 后半）的事。

use crate::ahci::{self, AhciError};

/// 状态区起始 LBA。**必须与 `tools/esp_image.py` 的同名常量同数**——
/// 门禁 `check-state-window` 逐字对账（两边各写一份数字而不核对，正是手册 V8 点名的形状）
pub const STATE_START_LBA: u64 = 67_648;
/// 一个槽 = 一个扇区（512 字节），8 个槽 ⇒ 整块区域 4 KiB
pub const SLOT_BYTES: usize = 512;
pub const N_SLOTS: u8 = 8;

const MAGIC: u32 = 0x4253_5541; // 'A' 'U' 'S' 'B'
/// V1 = 定长 28 字节的启动状态；V2 = 变长载荷（崩溃记录，§9.7 那张表里能真填上的那些字段）。
/// 解码器**同时认两版**：`§10.2 只增不改`在这里的字面含义是"旧记录在新代码里必须照读"，
/// 有判据（`KT_STATE_STORE` 的 `旧版照读`）。
pub const VERSION: u32 = 1;
pub const VERSION2: u32 = 2;
/// 头部 24 字节：`size`(0) `magic`(4) `version`(8) `kind`(12) `seq`(16..24)
const HDR: usize = 24;
/// 用例要往某一条记录的具体字段上写"自相矛盾"的数（帧数、长度），所以这两个偏移是公开的
pub const HDR_OFF: usize = HDR;
pub const CRASH_FIXED_OFF: usize = CRASH_FIXED;
/// V1 的 payload 定长 28 字节（`BootState` 的六个字段），校验和是紧随其后的 8 字节
const PAYLOAD: usize = 28;
/// 校验和槽位的上界：`size` 再大也不许越过这个缓冲
const MAX_PAYLOAD: usize = SLOT_BYTES - HDR - 8;
/// §9.7 的调用栈最多存这么多个返回地址。`32 × 8 + 64 = 320` 字节，**一个槽装得下** ——
/// 所以这里没有"跨槽续块"那套复杂度，那是被上界算过之后删掉的设计。
pub const MAX_FRAMES: usize = 32;
/// V2 崩溃记录里固定那段的长度（8 个 u32 + 4 个 u64）
const CRASH_FIXED: usize = 64;
/// §9.7 的"最近日志"（`kind = KIND_LOG`）固定段：`crash_seq`(8) + `lines`(4) + `bytes`(4)。
/// `crash_seq` 是它配的那条崩溃记录的 `seq` —— 没有这个数，两块区域里各自"最新"的记录
/// 谁配谁就没定义（重启之后崩溃记录可能已经换了一条，而日志尾还是更早那次的）。
const LOG_FIXED: usize = 16;
/// 一条槽装得下的日志文本上界：`480 - 16 = 464` 字节。按本机平均行长 ≈130 B 算约 3~4 行。
/// 要更多只有两条路：跨槽续块（那个设计在 56 行算过上界之后删过，不复活）或另开一块日志区
/// —— 后者是"持久日志"另一个特性，不在这一格。
pub const LOG_TEXT_MAX: usize = MAX_PAYLOAD - LOG_FIXED;
pub const LOG_FIXED_OFF: usize = LOG_FIXED;

/// 记录种类。`KIND_BOOT` 是 §9.4 的启动计数；`KIND_CRASH` 是 §9.7 的崩溃摘要 ——
/// 两者共用同一块区、同一套头部与校验和，靠 `kind` 分家。
pub const KIND_BOOT: u32 = 1;
pub const KIND_CRASH: u32 = 2;
pub const KIND_LOG: u32 = 3;
/// 只给用例用的第三种记录：验"种类过滤"与"共用游标"时不许借用 `KIND_CRASH` ——
/// 崩溃记录的正文形状是 V2，用 V1 的 28 字节冒充它，测的就不是生产路径的形状了。
pub const KIND_PROBE: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BootState {
    /// 连续失败启动次数。读不到 ⇒ 按"已经超过阈值"处理（判定的事在 `boot_guard`）
    pub failed_boots: u32,
    /// A/B 槽位（§9.5）：0=未知 1=good 2=trial 3=bad。这里只存
    pub good_slot: u32,
    pub bad_slot: u32,
    /// 上一次崩溃的粗线条摘要（L4 之前串口已经打了，下次启动由这条补"为什么"）
    pub last_vector: u32,
    pub last_cpu: u32,
    pub last_rip: u64,
}

/// §9.7 那张 `CrashRecord` 里**今天填得出真数**的那些字段。填不出的一律留 0 并在文件外写明：
/// * `process_id` —— 进程模型还没长出来（`thread_id` 是任务号，`current_id()` 给得到）；
/// * `module_id` —— 异常现场没有"哪个模块"这件事，只有驱动路径能给出，走 `dump_module`；
/// * 最近日志（`log_tail`）—— 需要停机路径可读的环形缓冲，另开一格，没在这里假装有。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashRecord {
    pub vector: u32,
    pub error_code: u32,
    pub cpu: u32,
    pub module_id: u32,
    /// §9.2 的级别（L1..L4）。停机路径上就是 4，但那个数要落盘才说得出口。
    pub fault_level: u32,
    pub thread_id: u32,
    pub process_id: u32,
    pub frame_count: u32,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub cr2: u64,
    pub frames: [u64; MAX_FRAMES],
}

impl Default for CrashRecord {
    fn default() -> Self {
        Self {
            vector: 0,
            error_code: 0,
            cpu: 0,
            module_id: 0,
            fault_level: 0,
            thread_id: 0,
            process_id: 0,
            frame_count: 0,
            rip: 0,
            rsp: 0,
            rbp: 0,
            cr2: 0,
            frames: [0u64; MAX_FRAMES],
        }
    }
}

/// §9.7 的"最近日志"读回来之后的形状：文本自己带一份缓冲，所以调用方不必再借一个。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LogTailData {
    /// 它配的那条崩溃记录的 `seq`
    pub crash_seq: u64,
    pub lines: u32,
    pub bytes: u32,
    pub text: [u8; LOG_TEXT_MAX],
}

impl Default for LogTailData {
    fn default() -> Self {
        Self { crash_seq: 0, lines: 0, bytes: 0, text: [0u8; LOG_TEXT_MAX] }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// 一个槽都没有有效记录（全新镜像、或全被写坏）⇒ 调用方按最坏情况处理
    NoValidSlot,
    /// 校验和/长度/magic 不符 ⇒ 这条被判为"读不到"，而不是"读到一个中间值"。
    /// `why` 留着，日志要说得出是哪一种
    Torn { slot: u8, why: &'static str },
    /// 版本不认识 ⇒ 不猜字段含义，直接算读不到
    Version(u32),
    /// 盘读不回来
    Io(AhciError),
}

fn g32(buf: &[u8; SLOT_BYTES], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

fn g64(buf: &[u8; SLOT_BYTES], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

fn put32(buf: &mut [u8; SLOT_BYTES], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// 校验和。用块层那台仪器已有的 FNV-1a 64（与 `tools/aurora.py` 同一实现），不是 CRC-32：
/// 这一格要挡的是"写了一半"，而它覆盖长度字段与全部 payload 就够用。
fn checksum(bytes: &[u8]) -> u64 {
    ahci::fnv1a64(bytes)
}

/// 只解头部并验长度界 + 校验和。两个版本都从这里过：**校验和覆盖"头部 + 全部 payload"**，
/// 而 `size` 是从盘上读来的数，所以用它做的每一次切片都要先过界（§10.3 同一条）。
/// 尾部那一帧被撕裂为什么读得出来？就因为 `used` 是按 `size` 算的，覆盖到了最后一条帧。
fn header(slot: u8, buf: &[u8; SLOT_BYTES]) -> Result<(u32, u64, u32, usize), StoreError> {
    let size = g32(buf, 0);
    if g32(buf, 4) != MAGIC {
        return Err(StoreError::Torn { slot, why: "magic 不符" });
    }
    let version = g32(buf, 8);
    if version != VERSION && version != VERSION2 {
        return Err(StoreError::Version(version));
    }
    if size == 0 || size as usize > MAX_PAYLOAD {
        return Err(StoreError::Torn { slot, why: "size 不在界内" });
    }
    let used = HDR + size as usize;
    if g64(buf, used) != checksum(&buf[..used]) {
        return Err(StoreError::Torn { slot, why: "校验和不符" });
    }
    Ok((g32(buf, 12), g64(buf, 16), version, size as usize))
}

/// 编一条 V2 崩溃记录。载荷长度是 `64 + 8 × 帧数`，**由记录自己决定**。
pub fn encode_crash(seq: u64, rec: &CrashRecord) -> [u8; SLOT_BYTES] {
    fn put(buf: &mut [u8], off: usize, v: &[u8]) {
        buf[off..off + v.len()].copy_from_slice(v);
    }
    let mut buf = [0u8; SLOT_BYTES];
    let n = (rec.frame_count as usize).min(MAX_FRAMES);
    let size = CRASH_FIXED + 8 * n;
    put(&mut buf, 0, &(size as u32).to_le_bytes());
    put(&mut buf, 4, &MAGIC.to_le_bytes());
    put(&mut buf, 8, &VERSION2.to_le_bytes());
    put(&mut buf, 12, &KIND_CRASH.to_le_bytes());
    put(&mut buf, 16, &seq.to_le_bytes());
    put(&mut buf, HDR, &rec.vector.to_le_bytes());
    put(&mut buf, HDR + 4, &rec.error_code.to_le_bytes());
    put(&mut buf, HDR + 8, &rec.cpu.to_le_bytes());
    put(&mut buf, HDR + 12, &rec.module_id.to_le_bytes());
    put(&mut buf, HDR + 16, &rec.fault_level.to_le_bytes());
    put(&mut buf, HDR + 20, &rec.thread_id.to_le_bytes());
    put(&mut buf, HDR + 24, &rec.process_id.to_le_bytes());
    put(&mut buf, HDR + 28, &(n as u32).to_le_bytes());
    put(&mut buf, HDR + 32, &rec.rip.to_le_bytes());
    put(&mut buf, HDR + 40, &rec.rsp.to_le_bytes());
    put(&mut buf, HDR + 48, &rec.rbp.to_le_bytes());
    put(&mut buf, HDR + 56, &rec.cr2.to_le_bytes());
    for i in 0..n {
        put(&mut buf, HDR + CRASH_FIXED + 8 * i, &rec.frames[i].to_le_bytes());
    }
    let used = HDR + size;
    let sum = checksum(&buf[..used]);
    put(&mut buf, used, &sum.to_le_bytes());
    buf
}

/// 解一条 V2 崩溃记录。**盘上的帧数先验界再用**：它必须与 `size` 自洽
/// （`size == 64 + 8 × 帧数`），否则就是"声称 32 帧而缓冲只到得了 4 帧"那一类越界读。
pub fn decode_crash(slot: u8, buf: &[u8; SLOT_BYTES]) -> Result<(u32, u64, CrashRecord), StoreError> {
    let (kind, seq, version, size) = header(slot, buf)?;
    if version != VERSION2 {
        return Err(StoreError::Torn { slot, why: "崩溃记录不是 V2" });
    }
    if size < CRASH_FIXED {
        return Err(StoreError::Torn { slot, why: "载荷比固定段还短" });
    }
    let frames = (size - CRASH_FIXED) / 8;
    if (size - CRASH_FIXED) % 8 != 0 || frames > MAX_FRAMES {
        return Err(StoreError::Torn { slot, why: "帧数与长度不自洽" });
    }
    let declared = g32(buf, HDR + 28) as usize;
    if declared != frames {
        return Err(StoreError::Torn { slot, why: "声明帧数与长度不自洽" });
    }
    let mut rec = CrashRecord {
        vector: g32(buf, HDR),
        error_code: g32(buf, HDR + 4),
        cpu: g32(buf, HDR + 8),
        module_id: g32(buf, HDR + 12),
        fault_level: g32(buf, HDR + 16),
        thread_id: g32(buf, HDR + 20),
        process_id: g32(buf, HDR + 24),
        frame_count: frames as u32,
        rip: g64(buf, HDR + 32),
        rsp: g64(buf, HDR + 40),
        rbp: g64(buf, HDR + 48),
        cr2: g64(buf, HDR + 56),
        ..CrashRecord::default()
    };
    for i in 0..frames {
        rec.frames[i] = g64(buf, HDR + CRASH_FIXED + 8 * i);
    }
    Ok((kind, seq, rec))
}

/// 编一条 V2 的"最近日志"记录：固定 16 字节 + 文本。
/// 这里**不做**"截断到上界"的体面处理，只 `min` 一下保证不越界 —— 真给多了说明上层
/// 没按整行取，而那种记录在 `decode_log` 那一关会因"末行不完整"被拒，不会安静存下来。
pub fn encode_log(seq: u64, crash_seq: u64, lines: u32, text: &[u8]) -> [u8; SLOT_BYTES] {
    let mut buf = [0u8; SLOT_BYTES];
    let n = text.len().min(LOG_TEXT_MAX);
    let size = LOG_FIXED + n;
    put32(&mut buf, 0, size as u32);
    put32(&mut buf, 4, MAGIC);
    put32(&mut buf, 8, VERSION2);
    put32(&mut buf, 12, KIND_LOG);
    buf[16..24].copy_from_slice(&seq.to_le_bytes());
    buf[HDR..HDR + 8].copy_from_slice(&crash_seq.to_le_bytes());
    put32(&mut buf, HDR + 8, lines);
    put32(&mut buf, HDR + 12, n as u32);
    buf[HDR + LOG_FIXED..HDR + LOG_FIXED + n].copy_from_slice(&text[..n]);
    let used = HDR + size;
    let sum = checksum(&buf[..used]);
    buf[used..used + 8].copy_from_slice(&sum.to_le_bytes());
    buf
}

/// 解一条 V2 的"最近日志"。自洽检查三条，一条比一条具体：
/// 声明长度必须等于 `size - 16`（与崩溃记录的"声明帧数"同一族）；末字节必须是换行；
/// 行数必须等于文本里换行符的真实个数 —— 后两条合起来就是"存进去的必须是整行"这件事
/// 在读侧的判据，环那边已经保证过一次，这里不许只靠上层自觉。
pub fn decode_log(slot: u8, buf: &[u8; SLOT_BYTES]) -> Result<(u32, u64, LogTailData), StoreError> {
    let (kind, seq, version, size) = header(slot, buf)?;
    if version != VERSION2 {
        return Err(StoreError::Torn { slot, why: "日志记录不是 V2" });
    }
    if size < LOG_FIXED {
        return Err(StoreError::Torn { slot, why: "载荷比固定段还短" });
    }
    let bytes = size - LOG_FIXED;
    if bytes > LOG_TEXT_MAX {
        return Err(StoreError::Torn { slot, why: "日志文本越界" });
    }
    if g32(buf, HDR + 12) as usize != bytes {
        return Err(StoreError::Torn { slot, why: "声明长度与长度不自洽" });
    }
    let off = HDR + LOG_FIXED;
    let end = off + bytes;
    if bytes > 0 && buf[end - 1] != b'\n' {
        return Err(StoreError::Torn { slot, why: "末行不完整" });
    }
    let real_lines = buf[off..end].iter().filter(|b| **b == b'\n').count() as u32;
    let declared_lines = g32(buf, HDR + 8);
    if real_lines != declared_lines {
        return Err(StoreError::Torn { slot, why: "行数与换行符数不符" });
    }
    let mut text = [0u8; LOG_TEXT_MAX];
    text[..bytes].copy_from_slice(&buf[off..end]);
    Ok((kind, seq, LogTailData {
        crash_seq: g64(buf, HDR),
        lines: declared_lines,
        bytes: bytes as u32,
        text,
    }))
}

/// 编一条记录（其余补 0）。纯函数 ⇒ 格式判据不必碰盘就能打。
pub fn encode(kind: u32, seq: u64, state: &BootState) -> [u8; SLOT_BYTES] {
    fn put(buf: &mut [u8], off: usize, v: &[u8]) {
        buf[off..off + v.len()].copy_from_slice(v);
    }
    let mut buf = [0u8; SLOT_BYTES];
    put(&mut buf, 0, &(PAYLOAD as u32).to_le_bytes());
    put(&mut buf, 4, &MAGIC.to_le_bytes());
    put(&mut buf, 8, &VERSION.to_le_bytes());
    put(&mut buf, 12, &kind.to_le_bytes());
    put(&mut buf, 16, &seq.to_le_bytes());
    put(&mut buf, HDR, &state.failed_boots.to_le_bytes());
    put(&mut buf, HDR + 4, &state.good_slot.to_le_bytes());
    put(&mut buf, HDR + 8, &state.bad_slot.to_le_bytes());
    put(&mut buf, HDR + 12, &state.last_vector.to_le_bytes());
    put(&mut buf, HDR + 16, &state.last_cpu.to_le_bytes());
    put(&mut buf, HDR + 20, &state.last_rip.to_le_bytes());
    let used = HDR + PAYLOAD;
    let sum = checksum(&buf[..used]);
    put(&mut buf, used, &sum.to_le_bytes());
    buf
}

/// 解一条 V1 启动记录。返回 `Err` 的几种情形**有意不细分到调用方**：处置都是"当没有"；
/// 但 `why` 留在错误里，日志说得出是哪一种。`kind` 由调用方比，不在这里当过滤器 ——
/// "种类认错"和"格式读不懂"是两种失败，混在一起红了也说不清是哪一件。
pub fn decode(slot: u8, buf: &[u8; SLOT_BYTES]) -> Result<(u32, u64, BootState), StoreError> {
    let (kind, seq, version, size) = header(slot, buf)?;
    if version != VERSION || size != PAYLOAD {
        return Err(StoreError::Torn { slot, why: "启动记录不是 V1 的 28 字节" });
    }
    let st = BootState {
        failed_boots: g32(buf, HDR),
        good_slot: g32(buf, HDR + 4),
        bad_slot: g32(buf, HDR + 8),
        last_vector: g32(buf, HDR + 12),
        last_cpu: g32(buf, HDR + 16),
        last_rip: g64(buf, HDR + 20),
    };
    Ok((kind, seq, st))
}

/// 按同一套算法把这条缓冲的校验和重算一遍。用例要构造"自相矛盾但校验和正确"的现场
/// （声称 32 帧而长度只到 4 帧），没有这个口子就只能靠"顺便把校验和也弄坏"，
/// 那样测的是校验和而不是长度自洽 —— 两格会合并成一格。
pub fn reseal(buf: &mut [u8; SLOT_BYTES]) {
    let size = g32(buf, 0) as usize;
    if size == 0 || size > MAX_PAYLOAD {
        return; // 长度本身就不在界内：这一格不是 reseal 的职责，交给 header 去拒
    }
    let used = HDR + size;
    let sum = checksum(&buf[..used]);
    buf[used..used + 8].copy_from_slice(&sum.to_le_bytes());
}

/// 第 `slot` 个槽的起始 LBA（用例要往某个槽里写"半条记录"来验撕裂，所以公开）
pub fn slot_lba(slot: u8) -> u64 {
    STATE_START_LBA + u64::from(slot) * (SLOT_BYTES as u64 / ahci::SECTOR)
}

/// 一次扫描的产出：整块区里 `seq` 最大的那条在哪（决定下一个槽与下一个 `seq`），
/// 以及 `want` 这个种类里**所有**头部有效的候选（按槽记，取的时候从大到小试）。
///
/// 候选是一个表而不是"最大那一条"，是因为头部过校验 != 正文解得开：只看头部就选最新，
/// 一条正文自相矛盾的记录会把整个种类锁死 —— 那是 §9.4 "坏记录不许把状态机卡住"的反面。
struct Found {
    any: Option<(u8, u64)>,
    cands: [(u8, u64); N_SLOTS as usize],
    n: usize,
    unusable: u8,
}

impl Found {
    /// 该种类里 `seq` 最大、且还没试过的候选。返回 None 表示候选用尽。
    fn next_candidate(&self, tried: &[(u8, u64); N_SLOTS as usize], tried_n: usize) -> Option<(u8, u64)> {
        let mut best: Option<(u8, u64)> = None;
        for i in 0..self.n {
            let (slot, seq) = self.cands[i];
            if tried[..tried_n].iter().any(|(s, q)| *s == slot && *q == seq) {
                continue;
            }
            if best.map(|(_, bseq)| bseq < seq).unwrap_or(true) {
                best = Some((slot, seq));
            }
        }
        best
    }
}

/// 扫描只看头部 ⇒ V1 与 V2 在同一次扫描里都能被认出来；类型化的解析在取回那一条之后再过。
/// 分两次扫每种记录就是把 8 次块读翻倍，而两件事必须同源：各自数各自的 `seq`，
/// "谁最新"就没有定义（§9.7 的崩溃记录进来之后就是这么撞的）。
fn scan(want: u32) -> Found {
    let mut found = Found { any: None, cands: [(0u8, 0u64); N_SLOTS as usize], n: 0, unusable: 0 };
    let port = match ahci::boot_port() {
        Ok(p) => p,
        Err(_) => {
            found.unusable = N_SLOTS;
            return found;
        }
    };
    for slot in 0..N_SLOTS {
        let mut buf = [0u8; SLOT_BYTES];
        if ahci::read_bytes(port, slot_lba(slot), &mut buf).is_err() {
            found.unusable += 1;
            continue;
        }
        match header(slot, &buf) {
            Ok((kind, seq, _, _)) => {
                if found.any.map(|(_, useq)| useq < seq).unwrap_or(true) {
                    found.any = Some((slot, seq));
                }
                if kind == want && found.n < N_SLOTS as usize {
                    found.cands[found.n] = (slot, seq);
                    found.n += 1;
                }
            }
            Err(_) => found.unusable += 1,
        }
    }
    found
}

/// 把某个槽原样读回来（`scan` 只看了头部，取正文要再读一次：多一次块读，换一条能同时
/// 服务两种记录的路径 —— 而不是为每种记录各扫一遍全区）
fn read_body(slot: u8) -> Result<[u8; SLOT_BYTES], StoreError> {
    let port = ahci::boot_port().map_err(StoreError::Io)?;
    let mut buf = [0u8; SLOT_BYTES];
    ahci::read_bytes(port, slot_lba(slot), &mut buf).map_err(StoreError::Io)?;
    Ok(buf)
}

/// 读某个种类的最新**能解开的**记录。没有 ⇒ `NoValidSlot`（最坏情况），
/// **没有**"读不到就当 0"那种默认值。
pub fn read(kind: u32) -> Result<(u8, u64, BootState), StoreError> {
    let found = scan(kind);
    let mut tried = [(0u8, 0u64); N_SLOTS as usize];
    let mut n_tried = 0usize;
    while let Some((slot, seq)) = found.next_candidate(&tried, n_tried) {
        tried[n_tried] = (slot, seq);
        n_tried += 1;
        match read_body(slot).and_then(|buf| decode(slot, &buf)) {
            Ok((k2, seq2, st)) if k2 == kind && seq2 == seq => return Ok((slot, seq, st)),
            Ok(_) => crate::log_warn!("state: 槽{} 的正文与头部不是同一条（被谁改过？）", slot),
            Err(e) => crate::log_warn!("state: 槽{} 头部有效而正文解不开 {:?}，退回下一条", slot, e),
        }
    }
    crate::log_info!("state: 种类 {} 没有有效记录（{} 个槽不可用），按最坏情况处理", kind, found.unusable);
    Err(StoreError::NoValidSlot)
}

/// 读最新那条崩溃记录（V2）。与 `read` 同一套候选与回退规则，只是解析成 `CrashRecord`
pub fn read_crash() -> Result<(u8, u64, CrashRecord), StoreError> {
    let found = scan(KIND_CRASH);
    let mut tried = [(0u8, 0u64); N_SLOTS as usize];
    let mut n_tried = 0usize;
    while let Some((slot, seq)) = found.next_candidate(&tried, n_tried) {
        tried[n_tried] = (slot, seq);
        n_tried += 1;
        match read_body(slot).and_then(|buf| decode_crash(slot, &buf)) {
            Ok((k2, seq2, rec)) if k2 == KIND_CRASH && seq2 == seq => return Ok((slot, seq, rec)),
            Ok(_) => crate::log_warn!("crash: 槽{} 的正文与头部不是同一条", slot),
            Err(e) => crate::log_warn!("crash: 槽{} 头部有效而正文解不开 {:?}，退回下一条", slot, e),
        }
    }
    crate::log_info!("crash: 没有解得开的崩溃记录（{} 个槽不可用）", found.unusable);
    Err(StoreError::NoValidSlot)
}

/// 读最新那条"最近日志"。候选与回退规则与 `read_crash` 同一条：头部有效而正文解不开 ⇒ 退回下一条，
/// 而不是让整个种类被一条自相矛盾的记录锁死。
pub fn read_log() -> Result<(u8, u64, LogTailData), StoreError> {
    let found = scan(KIND_LOG);
    let mut tried = [(0u8, 0u64); N_SLOTS as usize];
    let mut n_tried = 0usize;
    while let Some((slot, seq)) = found.next_candidate(&tried, n_tried) {
        tried[n_tried] = (slot, seq);
        n_tried += 1;
        match read_body(slot).and_then(|buf| decode_log(slot, &buf)) {
            Ok((k2, seq2, rec)) if k2 == KIND_LOG && seq2 == seq => return Ok((slot, seq, rec)),
            Ok(_) => crate::log_warn!("log-tail: 槽{} 的正文与头部不是同一条", slot),
            Err(e) => crate::log_warn!("log-tail: 槽{} 头部有效而正文解不开 {:?}，退回下一条", slot, e),
        }
    }
    Err(StoreError::NoValidSlot)
}

/// 下一个可写槽与它的 `seq`：**整块区**最大 `seq` + 1、槽位轮转。整块区都不可用时从 seq=1
/// 重新开始（坏记录不许把状态机永久卡住 —— 这一条有判据）。种类过滤器在这里用不上，
/// 传 `KIND_BOOT` 只是让 `scan` 的第二次返回值有个确定形状。
fn next_cursor() -> (u8, u64) {
    match scan(KIND_BOOT).any {
        Some((last, useq)) => ((last + 1) % N_SLOTS, useq.wrapping_add(1).max(1)),
        None => (0, 1),
    }
}

/// 写一条 V1 启动记录：换到下一个槽。轮转而不是原地覆盖，是为了让"写一半"只毁一个槽。
pub fn write(kind: u32, state: &BootState) -> Result<(u8, u64), StoreError> {
    let port = ahci::boot_port().map_err(StoreError::Io)?;
    let (slot, seq) = next_cursor();
    let buf = encode(kind, seq, state);
    ahci::write_bytes(port, slot_lba(slot), &buf).map_err(StoreError::Io)?;
    Ok((slot, seq))
}

/// 写一条 V2 崩溃记录，槽位与 `seq` 走同一个游标（两种记录共用一块区 ⇒ 共用一个计数）
pub fn write_crash(rec: &CrashRecord) -> Result<(u8, u64), StoreError> {
    let port = ahci::boot_port().map_err(StoreError::Io)?;
    let (slot, seq) = next_cursor();
    let buf = encode_crash(seq, rec);
    ahci::write_bytes(port, slot_lba(slot), &buf).map_err(StoreError::Io)?;
    Ok((slot, seq))
}

/// 抹掉整块区域：用例要把设备放回"全新镜像"的形状（`.ktests` 的顺序由链接器决定，
/// 不能让前一跑的残留决定后一跑读到什么）
/// 写一条"最近日志"。槽位与 `seq` 走同一个游标 ⇒ 三条记录共用一块区、一个计数，
/// "谁最新"始终有定义（M6-b① 立的那条规则在这里继续成立）。
/// 崩溃记录先写、日志尾后写，所以日志尾的 `seq` 比它配的那条大 1 —— 配对靠 `crash_seq` 那个数，
/// 不靠这个巧合。
pub fn write_log(crash_seq: u64, lines: u32, text: &[u8]) -> Result<(u8, u64), StoreError> {
    let port = ahci::boot_port().map_err(StoreError::Io)?;
    let (slot, seq) = next_cursor();
    let buf = encode_log(seq, crash_seq, lines, text);
    ahci::write_bytes(port, slot_lba(slot), &buf).map_err(StoreError::Io)?;
    Ok((slot, seq))
}

pub fn wipe() -> Result<(), StoreError> {
    let port = ahci::boot_port().map_err(StoreError::Io)?;
    for slot in 0..N_SLOTS {
        ahci::write_bytes(port, slot_lba(slot), &[0u8; SLOT_BYTES]).map_err(StoreError::Io)?;
    }
    Ok(())
}
