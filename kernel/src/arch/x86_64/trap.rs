//! CPU 描述符表、异常向量与故障探针。
//!
//! 描述符位布局按 Intel SDM Vol.3A 的段描述符/中断门格式逐字段算出，不是抄来的位常量。
//! CR2 的取值时机、错误码向量表、以及段选择子刷新这三处是最容易“看起来对、实际三重故障”
//! 的地方，每处都在下面标了依据。

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::serial;

pub const PAGE: usize = 4096;

// ---------------------------------------------------------------- 描述符构造

/// 代码/数据段描述符（低 qword）。
/// 字节->位域：b0-1 limit[0:16]、b2-4 base[0:24]、b5 access、
/// b6 低 nibble=limit[16:20] 高 nibble=flags(AVL/L/D/G)、b7 base[24:32]
const fn seg(access: u8, l_bit: bool, limit: u32, base: u64) -> u64 {
    let mut v: u64 = 0;
    v |= (limit as u64 & 0xffff) << 0;
    v |= (base & 0xffffff) << 16;
    v |= (access as u64) << 40;
    v |= ((limit as u64 >> 16) & 0xf) << 48;
    if l_bit {
        v |= 1 << 53; // b6 的 L 位（64 位代码段）；long mode 下 D/B 必须为 0
    }
    v |= ((base >> 24) & 0xff) << 56;
    v
}

/// 16 字节系统描述符（TSS）的高 qword：base[32:64]
const fn sys_desc_high(base: u64) -> u64 {
    base >> 32
}

/// 系统描述符低 qword。0x89 = present + type 9（64 位 available TSS）
const fn sys_desc_low(access_type: u8, base: u64, limit: u32) -> u64 {
    let mut v: u64 = 0;
    v |= (limit as u64 & 0xffff) << 0;
    v |= (base & 0xffffff) << 16;
    v |= (access_type as u64) << 40;
    v |= ((limit as u64 >> 16) & 0xf) << 48;
    v |= ((base >> 24) & 0xff) << 56;
    v
}

/// 中断/陷阱门：b0-1 offset[0:16]、b2-3 selector、b4 低 3 位=IST、b5 type|P、
/// b6-7 offset[16:32]、高 qword=offset[32:64]。
/// `dpl3=true` 把 bits[54:53] 置成 3：`int N` 想从 ring3 进门，门的 DPL 必须 ≤ 当前 CPL，
/// 否则 CPU 报 #GP(0) 而不是进门。只给 syscall 向量开这一位（M4-1 的 `int 0x80`），
/// 其它一律 DPL0 —— 给用户态开一个 DPL3 的异常门等于送一条提权入口。
const fn idt_gate(present: bool, ist: u8, selector: u16, handler: u64, trap_gate: bool, dpl3: bool) -> [u64; 2] {
    let ty: u8 = if trap_gate { 0x8F } else { 0x8E }; // 14=interrupt gate(关 IF)，15=trap gate
    let p: u8 = if present { 0x80 } else { 0x00 };
    let dpl_shifted: u64 = if dpl3 { 3 << 5 } else { 0 };
    let low = (handler & 0xffff)
        | ((selector as u64) << 16)
        | ((ist as u64) << 32)
        | (((ty | p) as u64) << 40)
        | (dpl_shifted << 40)
        | (((handler >> 16) & 0xffff) << 48);
    [low, handler >> 32]
}

// ---------------------------------------------------------------------- TSS

/// 架构规定的字段偏移（Intel SDM Vol.3A §7.3 与 64 位 TSS 的表）：
/// link@0、**RSP0@4**、RSP1@12、RSP2@20、保留@28、IST1..7@36..92、保留@92、IOMapBase@102。
const TSS_RSP0: usize = 4;
const TSS_IST1: usize = 36;
const TSS_IOMAP_BASE: usize = 102;
const TSS_BYTES: usize = 104;

/// 64 位 TSS。
/// **`packed` 不是省字节，是把 `rsp0` 放到偏移 4 的唯一写法**：`#[repr(C, align(16))]`
/// 会按自然对齐把它挪到偏移 8，而 CPU 从偏移 4 读 8 个字节 ⇒ 换栈换到一个被截断的地址
/// （#SS(0) → #DF → 三重故障，QEMU 以 rc=0 退出、一行判据都不留）。IST1 同样错 4 字节。
/// packed 字段不能取引用，所以读写一律 `addr_of_mut!` + `write_unaligned`；
/// 真实偏移由 `tss_offsets()` 用**字节视图**读回来交给用例核对，而不是靠 `offset_of!` 自证。
/// 现场与判据：BACKLOG 的 M4-1 缺陷表⑤、`t_user_roundtrip` 的 `tss_ok`。
#[repr(C, packed)]
pub struct Tss {
    /// link(16) + 保留(16)
    _link_rsv: u32,
    pub rsp0: u64,
    _rsp1: u64,
    _rsp2: u64,
    _reserved1: u64,
    /// ist[0] 即 IST1
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,
}

const _: () = assert!(core::mem::size_of::<Tss>() == TSS_BYTES);

impl Tss {
    const fn new() -> Self {
        Self {
            _link_rsv: 0,
            rsp0: 0,
            _rsp1: 0,
            _rsp2: 0,
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: TSS_BYTES as u16,
        }
    }
}

/// 用字节视图把 TSS 里**架构位置上的真值**读回来：(rsp0@4, ist1@36, iomap_base@102)。
///
/// 这是 `packed` 布局的第二台仪器：如果声明的偏移与架构不一致，这里读出来的数
/// 与 `set_rsp0`/`install_exception_stack` 写进去的数就对不上，而且对不上是**可判定的**，
/// 不需要等到 ring3 换栈去用一次三重故障当证明。
pub fn tss_offsets(slot: usize) -> Option<(u64, u64, u16)> {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return None;
    }
    // SAFETY: 只读本槽位自己的 TSS；用 `read_unaligned` 而不是引用，
    // 因为 packed 结构的字段可能不满足自然对齐（这正是本类型存在的理由）。
    unsafe {
        let base = core::ptr::addr_of_mut!((*TABLES[slot].0.get()).tss) as *const u8;
        Some((
            core::ptr::read_unaligned(base.add(TSS_RSP0) as *const u64),
            core::ptr::read_unaligned(base.add(TSS_IST1) as *const u64),
            core::ptr::read_unaligned(base.add(TSS_IOMAP_BASE) as *const u16),
        ))
    }
}

/// GDT 内容按 qword 计：null, code64, data64, **user data**, **user code**, tss(low), tss(high)
///
/// 用户段为什么必须在这儿而不是省事复用内核段：`iretq` 到 ring3 要求 CS/SS 的 RPL=3
/// 且描述符 DPL=3，否则 CPU 直接 #GP；而 DPL=0 的代码段被 ring3 拿到就是提权。
/// 顺序也定了选择子值：内核代码 0x08 / 内核数据 0x10 / 用户数据 0x1B / 用户代码 0x23。
/// 这不是为了好看：`SYSCALL`/`SYSRET` 的选择子是硬件从 `IA32_STAR` 两边各加 8/0x10 算出来的，
/// 这套排布正好对上（公式与装机值见 ADR-025 的"装机参数"表，判据是程序自己读回 CS/SS）。
const GDT_QWORDS: usize = 7;
const SEL_CODE: u64 = 0x08;
const SEL_DATA: u16 = 0x10;
/// 用户数据段（DPL3 + RPL3）
const SEL_USER_DATA: u16 = 0x1b;
/// 用户代码段（DPL3 + RPL3）
const SEL_USER_CODE: u64 = 0x23;
const SEL_TSS: u16 = 0x28;

/// 256 个门：0..31 是 CPU 异常，32..47 是 IRQ0..15，48..254 落到"不该出现的向量"桩，
/// 255 是本地 APIC 的 spurious 向量（协议把 SVR 设成 0x1FF，即向量 0xFF 且已使能）。
/// **255 必须单独一条桩**：spurious 中断不占用 ISR，按规范不能发 EOI，
/// 给它发 EOI 会多确认一个并不存在的服务中断——后果是别的中断收不到。
pub const IDT_ENTRIES: usize = 256;
pub const VEC_SPURIOUS: usize = 0xff;
pub const VEC_IRQ_BASE: usize = 32;
pub const VEC_IRQ_LAST: usize = 47;
/// 每个 CPU 的**本地** LAPIC 定时器向量。
///
/// 为什么不复用 32..47 里的某个 IRQ 槽：那一段是 I/O APIC 的 ISA 路由，GSI 与向量一一对应，
/// 而 LAPIC 内部定时器不经过 I/O APIC，占用 IRQ 槽会让"哪个外设在用这条线"变得说不清。
///
/// **M3b-2b 起这条向量走正常的异常帧路径**（`isr_stub_241` → `isr_common` → 抢占点），
/// 因为 AP 现在跑自己的运行队列，而不建帧就不可能换人。当初给它一条快路径的理由
/// —— "AP 的 tick 会混进 BSP 的 P5 样本" —— 现在由**按 CPU 分行的 P5 表**解决，
/// 不再靠"不记账"回避。
pub const VEC_CPU_TIMER: usize = 0xf1;
/// M4-1 的用户→内核入口向量（`int 0x80`）。
///
/// 为什么第一版用陷阱门而不是 `syscall`：`syscall` 硬件不切栈、不保存现场，
/// 入口必须先 `swapgs` 才能碰 per-CPU 数据，而 `swapgs` 与"切到内核栈"之间那个窗口
/// 正是 §5.3 R14 第 2 条挂着的评审项（手册在 §14 里写它"已定"，但 §5.3/A.5 都还写着
/// "本版本未规定"——这是一处文档自相矛盾，ADR-025 把它定下来）。
/// `int N` 走 IDT 门：硬件按 `TSS.rsp0` 自动换到内核栈、自动关 IF，
/// **那个窗口根本不存在**，因为这条路径上不需要 GS。先把"进得去、回得来、越界只杀用户"
/// 这条闭环建起来，SYSCALL 快路径留到 M4-2 与它一起设计。
pub const VEC_SYSCALL: usize = 0x80;

/// TLB shootdown（§6.6，向量 0xF2）。
/// 这条**仍然**是不建帧的快路径（`isr_stub_shootdown`），理由与本地定时器不同：
/// 它的请求方**正在等锁**，处理路径里任何一次取锁都会变成跨 CPU 死锁，
/// 而它也不需要抢占点（回执之后要继续做原来的活，不是换人）。
pub const VEC_SHOOTDOWN: usize = 0xf2;

/// 主动让出 / 重调度（ADR-049，P3a）。**软件中断**：`yield_now` 用 `int 0xF0` 自陷，
/// 硬件替我们压出异常帧，于是既有的 `isr_common → preempt_point` 原样可用，
/// 不需要第二套切换机制；而且 `int` 不受 IF 影响，**关着窗口也能让出**——
/// 这正是 `loads_closed` 一直缺的触发源。
/// 它**不置 LAPIC 的 ISR 位**，所以处理侧不发 EOI（与 spurious 同理，见 ADR-020）。
pub const VEC_RESCHED: usize = 0xf0;

/// 每 CPU 一套描述符表 + TSS + 异常栈：`rsp0`/`IST1` 天生是每 CPU 的，GDT 被 TSS 的地址拖着
/// 也必须 per-CPU，IDT 本可共享但仍放进同一套——免得"哪张表属于哪个 CPU"变成隐式约定。
/// 对齐 64 是为了相邻 CPU 不在同一条缓存行上互相拖慢，更为了不让人在不知情时写到别人的 TSS 里。
/// 成套复制的三层理由与 IF=0 的写入前提：ADR-024 的"补充（R35）"一节。
#[repr(C, align(64))]
struct Tables {
    gdt: [u64; GDT_QWORDS],
    idt: [[u64; 2]; IDT_ENTRIES],
    tss: Tss,
    /// #DF 独立栈（早期版本；MM 就绪后由 `install_exception_stack` 换成带 guard page 的栈）。
    /// bss 里的静态数组**无法**把它下面一页标成不可访问，所以这一段只是"分离的异常栈"。
    df_stack: [u8; PAGE],
}

#[repr(C, align(64))]
struct TablesSlot(UnsafeCell<Tables>);
// SAFETY: 每个 CPU 只写 `TABLES[自己的槽位]`，写发生在该 CPU 的 IF=0 阶段
// （BSP 在 kmain 早期，AP 在 ap_main 的第一步），之后只被硬件读。
// 跨槽位的写不会重叠，因为槽位是 64 字节对齐的独立对象。
// 这条 SAFETY 依赖 `cpu::reserve_ap_slot` 先把槽位分好且 id 不重复——那一步由 BSP 单线程完成。
unsafe impl Sync for TablesSlot {}

static TABLES: [TablesSlot; crate::arch::x86_64::cpu::MAX_CPUS] = [const {
    TablesSlot(UnsafeCell::new(Tables {
        gdt: [0; GDT_QWORDS],
        idt: [[0; 2]; IDT_ENTRIES],
        tss: Tss::new(),
        df_stack: [0u8; PAGE],
    }))
}; crate::arch::x86_64::cpu::MAX_CPUS];

/// 每个 CPU 的 #DF 栈区间。四张表都用原子量存：BSP 要在 `cpu::is_ready(slot)` 之后
/// 读 AP 自己写进去的数，用非原子的字段就得再造一把锁，而这里没有任何需要一起看的字段。
/// guard==0 表示这个槽位还没换上带 guard page 的栈（仍在用 .bss 那一页）。
static EX_GUARD: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static EX_LO: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
static EX_HI: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
/// 每个 CPU 的 #DF 栈顶（IST1 的值）。0 = 还在用 bss 里那页，没有 guard page。
static EX_STACK_TOP: [AtomicU64; crate::arch::x86_64::cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];
/// 本 CPU 的异常栈区间与栈顶，供用例逐项验证。
#[derive(Clone, Copy, Debug)]
pub struct ExStackInfo {
    pub guard_va: u64,
    pub stack_lo: u64,
    pub stack_hi: u64,
    pub top: u64,
}


/// lgdt/lidt 要的 10 字节伪描述符（limit:16 + base:64，小端，无对齐填充）。
/// 用字节数组而不是 packed 结构：packed 结构取引用本身就是个问题（E0587 同时禁止
/// packed 与 align 并存），按字节拼出来既没有布局歧义，也不需要 unsafe 取字段。
#[repr(C, align(16))]
struct Dtr([u8; 10]);

const fn dtr(limit: u16, base: u64) -> Dtr {
    let l = limit.to_le_bytes();
    let b = base.to_le_bytes();
    Dtr([l[0], l[1], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

extern "C" {
    /// asm 里的 32 个入口地址表，下标即向量号
    static isr_table: [u64; IDT_ENTRIES];
    /// TLB shootdown 桩的地址
    static isr_shootdown_gate: [u64; 1];
    fn flush_segments(code_sel: u64, data_sel: u16);
}

/// `isr_stub_shootdown` 的 Rust 侧入口。真正的 flush 在 `mm::shootdown_self`，
/// 这里只是一层不加任何逻辑的转发：转发层写薄，才看得出"这条路径上没有锁"。
#[no_mangle]
pub extern "C" fn aurora_shootdown() {
    crate::mm::shootdown_self();
}


/// 带错误码的向量（SDM Vol.3A 异常表）。本切片实际只走 13/14；
/// 其余按表安装，完整位表留给评审逐项核对，不当作既成事实。
const fn vectors_with_error_code() -> [bool; IDT_ENTRIES] {
    let mut t = [false; IDT_ENTRIES];
    t[8] = true; // #DF
    t[10] = true; // #TS
    t[11] = true; // #NP
    t[12] = true; // #SS
    t[13] = true; // #GP
    t[14] = true; // #PF
    t[17] = true; // #MF
    t[21] = true; // #AC
    t
}

/// 建立**本 CPU** 的 GDT/TSS/IDT。BSP 在 kmain 早期调用，AP 在 ap_main 第一步调用。
/// 每个槽位只由它自己的 CPU 写（见 TablesSlot 的 SAFETY 注释）。
pub fn init_cpu_tables(slot: usize) {
    // SAFETY: 见 TablesSlot 注释——本 CPU 的 IF=0 阶段，且只写自己那一槽。
    let t = unsafe { &mut *TABLES[slot].0.get() };

    t.gdt[0] = 0;
    t.gdt[1] = seg(0x9a, true, 0, 0); // code64, P=1, DPL0, S=1
    t.gdt[2] = seg(0x92, false, 0, 0); // data64, P=1, DPL0, S=1
    // 用户数据段：`0xf2 = P|DPL3|S|type2`。**这位 S(bit4) 当初漏了**——写成 0xe2 时
    // 低 4 位是 type2 而 S=0，整个描述符就变成"系统描述符，类型 2 = LDT"，
    // 于是 `iretq` 到 ring3 时装 SS=0x1b 判定为"不是一个数据段" ⇒ #GP。
    // QEMU 把错误码的 RPL 两位抹掉，报出来是 0x18（= 0x1b & ~3），
    // 现场看起来像"选择子值写错了"，其实选择子是对的、**描述符**是错的。
    // 这条现在有用例直接盯描述符位（见 `t_user_roundtrip` 的 segs_ok 判据），
    // 不再靠"跑到 ring3 挂了"反推。
    t.gdt[3] = seg(0xf2, false, 0, 0); // user data64, P=1, DPL3, S=1, 可写
    t.gdt[4] = seg(0xfa, true, 0, 0); // user code64, P=1, DPL3, S=1, type A + L 位
    let tss_addr = core::ptr::addr_of_mut!(t.tss) as u64;
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u32;
    t.gdt[5] = sys_desc_low(0x89, tss_addr, tss_limit);
    t.gdt[6] = sys_desc_high(tss_addr);

    // IST1 -> #DF 独立栈顶。先用 bss 里那一页（此刻 MM 可能还没就绪，BSP 的调用点在换页表之前）；
    // MM 就绪后由 install_exception_stack 换成带 guard page 的栈。
    let bss_df_top = ((t.df_stack.as_ptr() as u64) + PAGE as u64) & !0xf;
    // packed 字段不能取引用，一律 addr_of_mut! + write_unaligned（见 `Tss` 的注释）
    let ist1 = if slot < crate::arch::x86_64::cpu::MAX_CPUS {
        let v = EX_STACK_TOP[slot].load(Ordering::Relaxed);
        if v == 0 { bss_df_top } else { v }
    } else {
        bss_df_top
    };
    // SAFETY: 写自己那一槽的 TSS；偏移 36 才是架构规定的 IST1（`tss_offsets` 负责核对）
    unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), ist1) };

    let has_err = vectors_with_error_code();
    for v in 0..IDT_ENTRIES {
        let _ = has_err[v]; // 桩的形态由 asm 决定，这里只登记门
        // 外部中断（>=32）不允许用户态直接门（DPL 0）；异常里只有 #DF(8) 用 IST1，
        // 中断不需要 IST，因为它们本来就在 IF=0 的窗口里跑完。
        // 只有 shootdown 这一条需要绕过 `isr_table`：那张表在 242 那一格填的是
        // "不该出现的向量"共用桩，它会压 48 当向量号，把真正的 242 弄丢。
        // 本地定时器 241 已经有自己的 `isr_stub_241` 并在那张表里占好了位置（M3b-2b），
        // 所以不再需要特例——特例少一处，"哪个向量的现场是真的"这件事就少一处要记的规矩。
        let handler = if v == VEC_SHOOTDOWN {
            unsafe { isr_shootdown_gate[0] }
        } else {
            unsafe { isr_table[v] }
        };
        t.idt[v] = idt_gate(
            true,
            if v == 8 { 1 } else { 0 },
            SEL_CODE as u16,
            handler,
            v == 2,
            // 唯一的 DPL3 门：ring3 用它发起系统调用（M4-1 走 `int 0x80`，理由见 ADR-025）
            v == VEC_SYSCALL,
        );
    }

    let gdtr = dtr((core::mem::size_of_val(&t.gdt) - 1) as u16, t.gdt.as_ptr() as u64);
    let idtr = dtr((core::mem::size_of_val(&t.idt) - 1) as u16, t.idt.as_ptr() as u64);

    // SAFETY: gdtr/idtr 指向本槽位的表，生命周期等于内核；
    // 此刻本 CPU IF=0（BSP 由协议保证，AP 由 ap_entry 继承同一交接状态），
    // 不存在中途来中断看到半初始化状态的情况。
    unsafe {
        core::arch::asm!("lgdt [{}]", in(reg) &gdtr);
        flush_segments(SEL_CODE, SEL_DATA);
        core::arch::asm!("lidt [{}]", in(reg) &idtr);
        // ltr 的操作数是 r/m16：只能用 16 位通用寄存器，不能按 in(reg) 传 64 位寄存器
        core::arch::asm!("ltr ax", in("ax") SEL_TSS, options(nomem, nostack, preserves_flags));
    }
}

/// §6.4 里那条一直欠着的实现：给本 CPU 的 #DF 栈配一个**真的** guard page。
///
/// 保留 2 页 VA，只映射高那一页，低那一页永不映射 ⇒ 栈溢出越过边界就是 #PF，
/// 而不是写进邻居。做法与 `sched::spawn` 的任务栈同一条路数，判据也一样：
/// guard 未映射且访问它故障，栈内第一页已映射且访问它不故障（`t_exception_stack_guard`）。
///
/// 必须在 MM 就绪之后调用；`init_cpu_tables` 之后调用才会立刻生效（它读 EX_STACK_TOP），
/// 之前的 IDT 已经装好，IST1 只是 TSS 里的一个字段，改它不需要重装 IDT。
pub fn install_exception_stack(slot: usize) -> Result<ExStackInfo, crate::mm::MmError> {
    use crate::mm::{ModuleId, PageFlags, VirtAddr};
    const MOD_EXSTACK: ModuleId = ModuleId(13);
    let win = crate::mm::alloc_va_range(2).ok_or(crate::mm::MmError::OutOfMemory)?;
    let guard_va = win.0;
    let stack_lo = win.0 + crate::mm::PAGE as u64;
    let frames = crate::mm::phys_alloc(0, MOD_EXSTACK)?;
    let m = crate::mm::map(VirtAddr(stack_lo), frames, PageFlags::RW)?;
    core::mem::forget(m); // 异常栈与内核同寿命：没有"忘记解映射"这条路
    let stack_hi = win.0 + 2 * crate::mm::PAGE as u64;
    // IST1 用哪一页由 CPU 在切换到栈上时决定，必须 16 字节对齐
    let top = (stack_hi - 8) & !0xf;
    EX_LO[slot].store(stack_lo, Ordering::Relaxed);
    EX_HI[slot].store(stack_hi, Ordering::Relaxed);
    EX_STACK_TOP[slot].store(top, Ordering::Relaxed);
    // guard 最后发布：读到它非 0 就意味着其余三个数也已经写好（Release/Acquire 配对）
    EX_GUARD[slot].store(guard_va, Ordering::Release);
    // SAFETY: 见 TablesSlot——本 CPU 写自己那一槽的 TSS，此刻本 CPU IF=0
    let t = unsafe { &mut *TABLES[slot].0.get() };
    // SAFETY: packed 字段，见 `Tss` 注释；偏移由 `tss_offsets` 复核
    unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), top) };
    Ok(ExStackInfo { guard_va, stack_lo, stack_hi, top })
}

/// 某个 CPU 的异常栈读数；None = 还没换上带 guard page 的栈。
pub fn ex_stack_info(slot: usize) -> Option<ExStackInfo> {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return None;
    }
    let guard = EX_GUARD[slot].load(Ordering::Acquire);
    if guard == 0 {
        return None;
    }
    Some(ExStackInfo {
        guard_va: guard,
        stack_lo: EX_LO[slot].load(Ordering::Relaxed),
        stack_hi: EX_HI[slot].load(Ordering::Relaxed),
        top: EX_STACK_TOP[slot].load(Ordering::Relaxed),
    })
}

// ---------------------------------------------------------------- 异常处理

#[repr(C)]
pub struct TrapFrame {
    /// 桩在 GPR 之后压入 CR2，所以它是最低地址字段
    pub cr2: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// 已经取到过几次 #PF（供探针断言：没取到就是探针失效，必须能被发现）
pub static PF_TAKEN: AtomicUsize = AtomicUsize::new(0);
/// 异常桩要跳回的恢复地址；0 表示没有待恢复的探针。
/// 强制放 .data：这是 Rust 的不可变 static，不指定的话 LLVM 可能放进 .rodata，
/// 而异常桩要对它**写**，那会变成一次只读页写故障。
#[used]
#[no_mangle]
#[link_section = ".data"]
pub static PF_RESUME: AtomicU64 = AtomicU64::new(0);
/// 探针**预期**故障的那个 VA：与 `PF_RESUME` 配成一对，缺一个都不许恢复。
/// 只凭"`PF_RESUME` 非 0"就改 `frame.rip` 是放过一颗地雷：探针访的页若其实映射着，
/// 它根本不故障，`PF_RESUME` 就留在 .data 里，下一次无关的 #PF 会被它劫持（M4-1 实测：
/// 跳进探针尾巴的 `ret`，内核带着 0x3a000 去取指，看起来像入口写错了，其实入口代码没跑到）。
/// 所以恢复条件还要两条：CR2 必须等于登记的 VA（或落进 `PF_LO..PF_HI` 区间），
/// 且这次故障不许是**取指**故障。完整现场：BACKLOG 的 M4-1 缺陷表①。
#[used]
#[no_mangle]
#[link_section = ".data"]
pub static PF_EXPECT: AtomicU64 = AtomicU64::new(0);
/// §10.3 拷贝窗口的**区间**登记：`[PF_LO, PF_HI)`。与 `PF_EXPECT` 是同一台机器的两种用法——
/// 探针只访一个地址，而 `rep movsb` 会一路走过去，故障落在哪一页事先不知道。
/// 两条登记都由 `dispatch` 一次读齐并清空，所以不存在"恢复了但登记还在"。
#[used]
#[no_mangle]
#[link_section = ".data"]
pub static PF_LO: AtomicU64 = AtomicU64::new(0);
#[used]
#[no_mangle]
#[link_section = ".data"]
pub static PF_HI: AtomicU64 = AtomicU64::new(0);
/// 在拷贝窗口里被"接住"的故障次数。判据用它证明**恢复路径真的被走过**——
/// 一条没有证据的故障处理分支和没有它是一样的（§12.4.1 规则 3）。
pub static COPY_RECOVERED: AtomicU64 = AtomicU64::new(0);
/// 被"活着的地雷"撞上过的非预期 #PF 次数（每次都会把两条登记清掉，所以它数的是事件数）。
/// 用例把它当判据：正常路径必须是 0；不是 0 就说明恢复条件放过了一次劫持。
pub static PF_STALE_HITS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------- P3 / P5 量具（§12.4.1，per-CPU）
//
// 每张表只由它自己的 CPU 写（写时本 CPU IF=0），别的 CPU 只读来汇总——
// 全局一份的写法在 AP 之后就是跨 CPU 写同一格：min/max 被对方的样本改写，而 count 来自
// 另一台机器，出来的数看着完全正常。
// 跨 CPU 读一旦成立，**发布顺序就是必需的**（先写 sum/last/min/max，最后 Release 加 count；
// 读方先 Acquire 读 count）：规则与理由见手册 §12.4.1.1。
#[repr(C, align(64))]
#[derive(Default)]
pub struct StatsRow {
    pub entry: AtomicU64,
    pub p3_count: AtomicU64,
    pub p3_sum: AtomicU64,
    pub p3_last: AtomicU64,
    /// 下界初值取最大：这样第一次样本必然同时刷新 min 和 max，不会留一个假的 0
    pub p3_min: AtomicU64,
    pub p3_max: AtomicU64,
    pub p5_count: AtomicU64,
    pub p5_sum: AtomicU64,
    pub p5_last: AtomicU64,
    pub p5_min: AtomicU64,
    pub p5_max: AtomicU64,
    /// P5 里**不属于 ISA IRQ(32..47)** 的样本数。
    /// 为什么需要这一格：`p5 cross-check` 只报"两个数相不相等"，不相等时它不告诉你
    /// 差的是哪一类向量——排查只能靠猜（本仓库已经为这种猜付过一次学费）。
    /// `int 0x80` 污染 P5 那次是靠"差值正好等于调用数"反推出来的；这次直接把它记下来。
    /// P5 样本**按向量分桶**（只数 ISA IRQ 32..47，下标 = vector - 32）。
    /// 为什么不做成"两边总数相等"就完事：总数相等可以藏住"IRQ0 多一个、IRQ1 少一个"，
    /// 而这次要抓的恰恰是一个样本的来路。逐桶比对的判据更强，且红了会指名道姓。
    pub p5_hist: [AtomicU64; VEC_IRQ_LAST - VEC_IRQ_BASE + 1],
    pub p5_non_irq: AtomicU64,
    /// 分流 debug 用：本 CPU 最后一次进 P5 表的向量号。正常应当永远是 32..47 或本地定时器的 0xF1。
    /// 这个格子同时是"上界那一步没写歪"的证据——它曾经因为偏移算错读到的是故障现场的 rdx。
    pub p5_last_vec: AtomicU64,
    pub f_count: AtomicU64,
    pub f_sum: AtomicU64,
    pub f_last: AtomicU64,
    pub f_min: AtomicU64,
    pub f_max: AtomicU64,
    /// P7：`int 0x80` 的往返延迟（本 CPU）。**必须与 P5 分开**，理由见 `record_sample`。
    /// `sc_lead[0..4]` = 本 CPU **前四次**被记账的代价，按到达顺序存。
    /// 为什么是四格而不是一个 `first`：`first=100505 / min=186 / cold=3 / runs=1` 这组数
    /// 已经把"每次被换上来才冷"那条假设**否掉了**（任务只被换上来一次，却打了 32 次调用），
    /// 于是下一个问题变成"那 3 个冷样本落在第几次上"——只有按位置存才答得了这个问题。
    pub sc_lead: [AtomicU64; 4],
    /// P7 的"冷样本"计数：代价 >= `P7_COLD_CYCLES` 的样本数。
    /// 为什么 `min/max/mean` 不够：1 个冷样本和 15 个冷样本可以有同一个 `min`，
    /// 而这两者的处置完全不同（前者是"第一次碰这条栈"，后者是"每次被换上来都重新冷"——
    /// 后者意味着用户态的代价主要由**调度交错**决定，换入口指令救不了它）。
    pub sc_cold: AtomicU64,
    pub sc_count: AtomicU64,
    pub sc_sum: AtomicU64,
    pub sc_last: AtomicU64,
    pub sc_min: AtomicU64,
    pub sc_max: AtomicU64,
    /// 快路径（`syscall` 指令）那一套，与 `sc_*` 同构。ADR-025 规定两条入口比 warm
    /// `min` 与 `cold`，合在一张表里就永远比不了。
    pub sf_lead: [AtomicU64; 4],
    pub sf_cold: AtomicU64,
    pub sf_count: AtomicU64,
    pub sf_sum: AtomicU64,
    pub sf_min: AtomicU64,
    pub sf_max: AtomicU64,
}

/// P7 的"算冷"门槛（周期）。**它是分类阈值，不是硬件常数**：
/// 取的是"同一条路径的 warm min（实测 179）与第一个样本（实测 82,457）之间"的一个
/// 整数位，用来把样本分成"和 warm 同量级"与"高出两个数量级"两堆。
/// 换机器或换 QEMU 版本时这个数要重看（`docs/testing/p4-tolerance.md` 同一条纪律）。
pub const P7_COLD_CYCLES: u64 = 10_000;

const fn new_row() -> StatsRow {
    StatsRow {
        entry: AtomicU64::new(0),
        p3_count: AtomicU64::new(0),
        p3_sum: AtomicU64::new(0),
        p3_last: AtomicU64::new(0),
        p3_min: AtomicU64::new(u64::MAX),
        p3_max: AtomicU64::new(0),
        p5_count: AtomicU64::new(0),
        p5_sum: AtomicU64::new(0),
        p5_last: AtomicU64::new(0),
        p5_min: AtomicU64::new(u64::MAX),
        p5_max: AtomicU64::new(0),
        p5_last_vec: AtomicU64::new(0),
        sc_lead: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
        p5_hist: [
            AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
            AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
            AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
            AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
        ],
        p5_non_irq: AtomicU64::new(0),
        sc_cold: AtomicU64::new(0),
        sc_count: AtomicU64::new(0),
        sc_sum: AtomicU64::new(0),
        sc_last: AtomicU64::new(0),
        sc_min: AtomicU64::new(u64::MAX),
        sc_max: AtomicU64::new(0),
        sf_lead: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
        sf_cold: AtomicU64::new(0),
        sf_count: AtomicU64::new(0),
        sf_sum: AtomicU64::new(0),
        sf_min: AtomicU64::new(u64::MAX),
        sf_max: AtomicU64::new(0),
        f_count: AtomicU64::new(0),
        f_sum: AtomicU64::new(0),
        f_last: AtomicU64::new(0),
        f_min: AtomicU64::new(u64::MAX),
        f_max: AtomicU64::new(0),
    }
}

#[repr(C, align(64))]
struct StatsTable(core::cell::UnsafeCell<[StatsRow; crate::arch::x86_64::cpu::MAX_CPUS]>);
// SAFETY: 每个 CPU 只写自己那一行（写的时候本 CPU IF=0，不会与本 CPU 的第二个异常交错），
// 跨 CPU 只有读，而且读的是 AtomicU64。行大小 64 字节对齐，所以两核不会落在同一行里互相拖慢。
unsafe impl Sync for StatsTable {}
static STATS: StatsTable = StatsTable(core::cell::UnsafeCell::new([const { new_row() }; crate::arch::x86_64::cpu::MAX_CPUS]));

/// 本 CPU 的槽位由调用方传进来，**不在这里读 LAPIC**。
///
/// 理由是一条实测的代价，不是风格：`cpu::self_slot()` 要读一次 UC- 的 MMIO 寄存器，
/// 在本机 QEMU 上这一次读的代价足以改变被测的东西——P1 的 `min` 从 M3b-1 的 462~987
/// 涨到 2536~2784，而涨的那一段就是在 `preempt_point` 里多读了三次 LAPIC id
/// （`current_id()`、`entry_tsc()`、`p3_record_irq()` 各自查了一次）。
/// 所以异常入口取一次槽位，往下传；这条约定同时让"每次中断只问一次我是谁"变成可见的结构。
#[inline]
fn row(slot: usize) -> &'static StatsRow {
    // SAFETY: 见 StatsTable；slot 由调用方保证 < MAX_CPUS
    unsafe { &(*STATS.0.get())[slot] }
}

/// 本 CPU 本次异常的下界读数。由 `aurora_trap_entry` 在最早处写一次。
pub fn mark_entry(cpu: usize, t: u64) {
    row(cpu).entry.store(t, Ordering::Relaxed);
}

/// 某 CPU 的进桩时刻，供**不返回**的那条路径（致命出口）自己算耗时。
pub fn entry_tsc_of(cpu: usize) -> u64 {
    row(cpu).entry.load(Ordering::Relaxed)
}

/// 两个系统调用入口都算 P7。`VEC_SYSCALL_FAST` 不是架构向量，是我们自己标的
/// "这条样本从哪个入口来"，所以它绝不能落进 P5 或"非 ISA 样本"那一格。
pub fn is_syscall_vector(v: u64) -> bool {
    v == VEC_SYSCALL as u64 || v == VEC_SYSCALL_FAST
}

/// P7 记账。**两条入口、两套格子、一份代码**：分流规则上次写在两处只改了一处（⑧），
/// 这次把它收成单点，剩下的只有"这条样本进哪一套格子"。
fn p7_record(r: &StatsRow, vector: u64, cost: u64) {
    let fast = vector == VEC_SYSCALL_FAST;
    // `fetch_add` 返回加之前的值，正好是本次样本的下标：不用锁，也不会两次撞进同一格。
    let (lead, count, sum, cold, min, max, last) = if fast {
        (&r.sf_lead, &r.sf_count, &r.sf_sum, &r.sf_cold, &r.sf_min, &r.sf_max, None)
    } else {
        (&r.sc_lead, &r.sc_count, &r.sc_sum, &r.sc_cold, &r.sc_min, &r.sc_max, Some(&r.sc_last))
    };
    let idx = count.fetch_add(1, Ordering::Relaxed);
    if idx < lead.len() as u64 {
        lead[idx as usize].store(if cost == 0 { 1 } else { cost }, Ordering::Relaxed);
    }
    if cost >= P7_COLD_CYCLES {
        cold.fetch_add(1, Ordering::Relaxed);
    }
    sum.fetch_add(cost, Ordering::Relaxed);
    if let Some(l) = last {
        l.store(cost, Ordering::Relaxed);
    }
    min.fetch_min(cost, Ordering::Relaxed);
    max.fetch_max(cost, Ordering::Relaxed);
}

/// 快路径那套格子的读数（用例并排打印两条入口用）。
pub fn p7_fast_of(slot: usize) -> (u64, u64, u64, [u64; 4]) {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return (0, 0, 0, [0; 4]);
    }
    let r = row(slot);
    let n = r.sf_count.load(Ordering::Acquire);
    (
        n,
        if n == 0 { 0 } else { r.sf_min.load(Ordering::Relaxed) },
        r.sf_cold.load(Ordering::Relaxed),
        [
            r.sf_lead[0].load(Ordering::Relaxed),
            r.sf_lead[1].load(Ordering::Relaxed),
            r.sf_lead[2].load(Ordering::Relaxed),
            r.sf_lead[3].load(Ordering::Relaxed),
        ],
    )
}

/// 记一个样本：`vector >= 32` 进中断延迟表（P5），否则进 #PF 恢复表（P3）。
/// 两条路径（正常 iretq 返回、以及被 `context_load` 换出去）都调这一个函数，
/// 所以"哪条路径漏记一个样本"这种错已经不可能各记一半了——但也因此失去了一台独立仪器，
/// 补偿办法是把对照对象留在**另一个模块**：用例比较的是"P5 样本数"与
/// `apic` 那侧按向量分头的计数（写者不同、路径不同），见 `t_timer_ticks_recur`。
pub fn record_sample(cpu: usize, vector: u64, cost_cycles: u64) {
    let r = row(cpu);
    // **按来源分流，不按"向量号 ≥ 32"**。P5 的定义是"外部中断从进桩到返回的延迟"，
    // 而 `int 0x80` 的号(0x80)虽然落在 ≥32 的数值区间里，它根本不是外部中断：
    // 它是用户程序的主动调用，延迟里包含 ABI 的分发与返回值写回。
    // 这一条是 M4-2 的"两台仪器必须数到同一个数"抓出来的：加载并跑起真 ELF 之后
    // `asm_samples=44 / rust_samples=41`，差的正好是那三次系统调用。
    // 把它留在 P5 里，等于让中断延迟基线随用户程序的调用次数漂移——两个基线都废。
    if is_syscall_vector(vector) {
        p7_record(r, vector, cost_cycles);
    } else if vector >= VEC_IRQ_BASE as u64 {
        // 本地 APIC 定时器(0xF1)一类非 ISA 向量：驱动侧的 `irq[]` **刻意不数**它们，
        // 所以它们是"两台仪器差值"的合法来源，必须单独数出来才能判断差得对不对。
        if vector > VEC_IRQ_LAST as u64 {
            r.p5_non_irq.fetch_add(1, Ordering::Relaxed);
        } else {
            r.p5_hist[(vector - VEC_IRQ_BASE as u64) as usize].fetch_add(1, Ordering::Relaxed);
        }
        r.p5_sum.fetch_add(cost_cycles, Ordering::Relaxed);
        r.p5_last.store(cost_cycles, Ordering::Relaxed);
        r.p5_last_vec.store(vector, Ordering::Relaxed);
        r.p5_min.fetch_min(cost_cycles, Ordering::Relaxed);
        r.p5_max.fetch_max(cost_cycles, Ordering::Relaxed);
        r.p5_count.fetch_add(1, Ordering::Release);
    } else {
        r.p3_sum.fetch_add(cost_cycles, Ordering::Relaxed);
        r.p3_last.store(cost_cycles, Ordering::Relaxed);
        r.p3_min.fetch_min(cost_cycles, Ordering::Relaxed);
        r.p3_max.fetch_max(cost_cycles, Ordering::Relaxed);
        r.p3_count.fetch_add(1, Ordering::Release);
    }
}

/// 抢占式离开时补记一次中断延迟样本（这条路径不经过 `aurora_trap_entry` 的出口记账）。
pub fn p3_record_irq(cpu: usize, cost_cycles: u64) {
    let r = row(cpu);
    // **同一条分流规则，两个入口**。上一次给 P5/P7 分流时我只改了出口那条
    // （`record_sample`），漏了这一条——后果是 `p5 cross-check` 的总数还差 1，
    // 而逐桶比对把真相摊开：`P5=[15,...]` vs `驱动=[47,...]`，
    // 差的全是"被这次陷阱换出去"的那批样本（正常返回走出口、被抢占走这里）。
    // 也就是说：**一条规则写在两处，就必须有两处各自的判据**；
    // 这里读 ISR 入口处记下的 `p5_last_vec`，不重新读 LAPIC（一次 UC- 读约 600 周期）。
    let v = r.p5_last_vec.load(Ordering::Relaxed);
    if is_syscall_vector(v) {
        p7_record(r, v, cost_cycles);
        return;
    }
    if v > VEC_IRQ_LAST as u64 {
        r.p5_non_irq.fetch_add(1, Ordering::Relaxed);
    } else if v >= VEC_IRQ_BASE as u64 {
        r.p5_hist[(v - VEC_IRQ_BASE as u64) as usize].fetch_add(1, Ordering::Relaxed);
    }
    r.p5_sum.fetch_add(cost_cycles, Ordering::Relaxed);
    r.p5_last.store(cost_cycles, Ordering::Relaxed);
    r.p5_min.fetch_min(cost_cycles, Ordering::Relaxed);
    r.p5_max.fetch_max(cost_cycles, Ordering::Relaxed);
    r.p5_count.fetch_add(1, Ordering::Release);
}

/// 致命路径的账（第三条表：判定到可以停机，不含现场打印）。
pub fn p3_record_fatal(cpu: usize, cost_cycles: u64) {
    let r = row(cpu);
    r.f_sum.fetch_add(cost_cycles, Ordering::Relaxed);
    r.f_last.store(cost_cycles, Ordering::Relaxed);
    r.f_min.fetch_min(cost_cycles, Ordering::Relaxed);
    r.f_max.fetch_max(cost_cycles, Ordering::Relaxed);
    r.f_count.fetch_add(1, Ordering::Release);
}

#[derive(Clone, Copy)]
pub struct P3Stats {
    pub faults: u64,
    pub mean_cycles: u64,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub last_cycles: u64,
    /// 只有 P7 用得上：第一个被记账的样本（其它表保持 0）
    pub first_cycles: u64,
    /// 只有 P7 用得上：代价 >= `P7_COLD_CYCLES` 的样本数
    pub cold_samples: u64,
}

/// 一个 CPU 的三张表 + 最后一个中断向量号。
#[derive(Clone, Copy)]
pub struct CpuPStats {
    pub cpu: usize,
    pub resume: P3Stats,
    pub irq: P3Stats,
    pub fatal: P3Stats,
    /// P7：本 CPU 的系统调用往返（`first_cycles` 这一格要用 `stats_syscall_of` 才有值）
    pub syscall: P3Stats,
    /// P5 中不属于 ISA IRQ(32..47) 的样本数（见 `StatsRow::p5_non_irq`）
    pub p5_non_irq: u64,
    pub last_vec: u64,
}

fn stats_of_row(count: &AtomicU64, sum: &AtomicU64, min: &AtomicU64, max: &AtomicU64, last: &AtomicU64) -> P3Stats {
    // 先 acquire 读 count，再读其余：见上面的发布顺序
    let n = count.load(Ordering::Acquire);
    let s = sum.load(Ordering::Relaxed);
    P3Stats {
        faults: n,
        mean_cycles: if n == 0 { 0 } else { s / n },
        min_cycles: if n == 0 { 0 } else { min.load(Ordering::Relaxed) },
        max_cycles: max.load(Ordering::Relaxed),
        last_cycles: last.load(Ordering::Relaxed),
        first_cycles: 0,
        cold_samples: 0,
    }
}

/// P7 专用：带"第一个样本"的读法（别的表不配这一格，所以单独一个函数）。
pub fn stats_syscall_of(slot: usize) -> P3Stats {
    let mut s = stats_of_cpu(slot).syscall;
    if slot < crate::arch::x86_64::cpu::MAX_CPUS {
        s.first_cycles = row(slot).sc_lead[0].load(Ordering::Relaxed);
        s.cold_samples = row(slot).sc_cold.load(Ordering::Relaxed);
    }
    s
}

pub fn stats_of_cpu(slot: usize) -> CpuPStats {
    let r = row(slot);
    CpuPStats {
        cpu: slot,
        resume: stats_of_row(&r.p3_count, &r.p3_sum, &r.p3_min, &r.p3_max, &r.p3_last),
        irq: stats_of_row(&r.p5_count, &r.p5_sum, &r.p5_min, &r.p5_max, &r.p5_last),
        fatal: stats_of_row(&r.f_count, &r.f_sum, &r.f_min, &r.f_max, &r.f_last),
        syscall: stats_of_row(&r.sc_count, &r.sc_sum, &r.sc_min, &r.sc_max, &r.sc_last),
        p5_non_irq: r.p5_non_irq.load(Ordering::Relaxed),
        last_vec: r.p5_last_vec.load(Ordering::Relaxed),
    }
}

/// 已登记 CPU 的读数快照（含还没样本的 CPU，供日志一行打完）。
pub fn p_stats_all() -> [CpuPStats; crate::arch::x86_64::cpu::MAX_CPUS] {
    let mut out = [CpuPStats {
        cpu: 0,
        resume: P3Stats { faults: 0, mean_cycles: 0, min_cycles: 0, max_cycles: 0, last_cycles: 0, first_cycles: 0, cold_samples: 0 },
        irq: P3Stats { faults: 0, mean_cycles: 0, min_cycles: 0, max_cycles: 0, last_cycles: 0, first_cycles: 0, cold_samples: 0 },
        fatal: P3Stats { faults: 0, mean_cycles: 0, min_cycles: 0, max_cycles: 0, last_cycles: 0, first_cycles: 0, cold_samples: 0 },
        syscall: P3Stats { faults: 0, mean_cycles: 0, min_cycles: 0, max_cycles: 0, last_cycles: 0, first_cycles: 0, cold_samples: 0 },
        p5_non_irq: 0,
        last_vec: 0,
    }; crate::arch::x86_64::cpu::MAX_CPUS];
    for (i, o) in out.iter_mut().enumerate() {
        *o = stats_of_cpu(i);
    }
    out
}

/// 所有 CPU 的中断延迟样本总数（跨 CPU 对照用的那一台仪器在 `apic` 那侧）。
/// 某个 CPU 的 P5 逐向量样本数（下标 = vector - 32）。
pub fn p5_hist_of(slot: usize) -> [u64; VEC_IRQ_LAST - VEC_IRQ_BASE + 1] {
    let mut out = [0u64; VEC_IRQ_LAST - VEC_IRQ_BASE + 1];
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return out;
    }
    let r = row(slot);
    for (o, v) in out.iter_mut().zip(r.p5_hist.iter()) {
        *o = v.load(Ordering::Relaxed);
    }
    out
}

/// P5 中非 ISA-IRQ 的样本数（逐 CPU 可读，BSP 用 `p5_non_irq()`）。
pub fn p5_non_irq_of(slot: usize) -> u64 {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return 0;
    }
    row(slot).p5_non_irq.load(Ordering::Relaxed)
}

pub fn p5_non_irq() -> u64 {
    p5_non_irq_of(crate::arch::x86_64::cpu::BSP_SLOT)
}

pub fn p5_samples_total() -> u64 {
    (0..crate::arch::x86_64::cpu::MAX_CPUS).map(|s| stats_of_cpu(s).irq.faults).sum()
}

/// 合法补页/恢复路径的样本总数（跨 CPU）。
pub fn p3_faults_total() -> u64 {
    (0..crate::arch::x86_64::cpu::MAX_CPUS).map(|s| stats_of_cpu(s).resume.faults).sum()
}

/// 下面三个 `*_stats()` 是 **BSP 那一份**的读数：手册 §12.4.1 与 `tools/aurora.py bench`
/// 的解析格式从这个形状来（`p3 resume: faults= mean= min= max=`），改成跨 CPU 汇总
/// 会让历史基线不可比，也看不出是哪个核。跨 CPU 的数走 `p_stats_all()` 单独打一行。
pub fn p3_resume_stats() -> P3Stats {
    stats_of_cpu(crate::arch::x86_64::cpu::BSP_SLOT).resume
}

pub fn p5_irq_stats() -> P3Stats {
    stats_of_cpu(crate::arch::x86_64::cpu::BSP_SLOT).irq
}

/// 本 CPU 最后一次进异常路径的向量号。
/// 由 `aurora_trap_entry` 在最早处写一次，所以**两条记账路径都能看到它**：
/// 正常返回的那条走 `record_sample`，而被 `context_load` 换出去的那条走 `p3_record_irq`，
/// 后者根本不知道自己服务的是哪个向量。AP 上每个 tick 都换人，
/// 因此如果只在 `record_sample` 里写这一格，AP 的 `last_vec` 会永远是 0——
/// 那不是量具坏了，是读数点选错了位置；把读数点提到入口处就不用猜。
pub fn note_last_vec(cpu: usize, v: u64) {
    row(cpu).p5_last_vec.store(v, Ordering::Relaxed);
}

/// P7 的第一次样本代价（0 = 还没有任何系统调用）。`1` 是"实测为 0 周期"的占位
/// （不能拿 0 当"没记过"的哨兵，所以真实读数下压到 1，代价是 0 与 1 分不开——
/// 而 0 周期的系统调用本来就不存在）。
pub fn p7_first() -> u64 {
    stats_syscall_of(crate::arch::x86_64::cpu::BSP_SLOT).first_cycles
}

/// P7 前四次样本的代价（不足四次的位置保持 0）。
pub fn p7_lead() -> [u64; 4] {
    let mut out = [0u64; 4];
    if crate::arch::x86_64::cpu::BSP_SLOT >= crate::arch::x86_64::cpu::MAX_CPUS {
        return out;
    }
    let r = row(crate::arch::x86_64::cpu::BSP_SLOT);
    for (o, v) in out.iter_mut().zip(r.sc_lead.iter()) {
        *o = v.load(Ordering::Relaxed);
    }
    out
}

pub fn p5_last_vec() -> u64 {
    stats_of_cpu(crate::arch::x86_64::cpu::BSP_SLOT).last_vec
}

/// 非法访问终止路径：从进桩到「判定致命、打完现场、准备停机」的周期数。
/// 与上面那张表**分开**是手册 §12.4.1 的要求（两条路径分别计），合在一张表里
/// 就等于把 200 周期的恢复和 20 周期的停机混成一个均值，谁都不能用。
pub fn p3_fatal_stats() -> P3Stats {
    stats_of_cpu(crate::arch::x86_64::cpu::BSP_SLOT).fatal
}

pub enum Action {
    Resume,
    /// 来自用户态的故障：**只终止这个任务**，内核继续跑（§9.2 的分级 + 立项那条
    /// "一个错误不拖垮整个系统"）。与 Fatal 的区别就是这一条判据有没有落到 ring3 上。
    Kill,
    /// 任务**自己**要求结束（`SYS_EXIT`）。与 `Kill` 分开，因为判据要能回答两件
    /// 不同的事："越界的用户程序被隔离掉了"和"任务生命周期走完了、资源回账了"。
    /// 混成一个动作，前者一旦回归就会看不出来（杀掉一切都能"顺便回收"）。
    Exit,
    Fatal,
}

/// 异常分发。本切片还没有"用户态 → 内核的故障隔离矩阵"那么细，
/// 但有一条已经必须先立起来：**从 ring3 来的异常不许停机**。
/// 没有这条的话，一个用户程序的野指针就是整台机器（§1.1 的立项理由）。
pub fn dispatch(frame: &mut TrapFrame) -> Action {
    if is_syscall_vector(frame.vector) {
        return if (crate::hooks::sched().syscall_dispatch)(frame) {
            Action::Exit
        } else {
            Action::Resume
        };
    }
    if frame.vector >= VEC_IRQ_BASE as u64 {
        // 外部中断。计数与 EOI 的规则都在 apic 里，这里只负责"它不是异常"。
        crate::arch::x86_64::apic::on_interrupt(frame.vector as usize);
        return Action::Resume;
    }
    if frame.vector == 14 {
        PF_TAKEN.fetch_add(1, Ordering::Relaxed);
        let resume = PF_RESUME.swap(0, Ordering::AcqRel);
        let expect = PF_EXPECT.swap(0, Ordering::AcqRel);
        // §10.3 的拷贝窗口用的是**区间**登记（`PF_LO..PF_HI`），不是单点：
        // `rep movsb` 会一路读过去，故障落在这一段的哪一页事先不知道，
        // 但"落在不在这一段里"是完全可判的。两者共用同一条恢复逻辑，所以在这里
        // 一次读齐四格（`swap(0)` 顺手清空——登记的成对性由这一次读统一保证，
        // 不留"恢复了但登记还在"的形状，那正是 M4-1 那颗地雷的成因）。
        let lo = PF_LO.swap(0, Ordering::AcqRel);
        let hi = PF_HI.swap(0, Ordering::AcqRel);
        // 恢复的三个条件（缺一律按"非预期故障"处理，见 PF_EXPECT 的注释）：
        // 登记过恢复地址、这次故障的地址是登记过的那一格**或落在那个区间里**、
        // 且它不是取指故障（bit4=1 = instruction fetch；探针与拷贝都只做 load/store，
        // 取指故障绝不可能是它们造成的）。
        let hit_point = expect != 0 && expect == frame.cr2;
        let hit_range = hi != 0 && frame.cr2 >= lo && frame.cr2 < hi;
        if resume != 0 && (hit_point || hit_range) && (frame.error_code & 0x10) == 0 {
            if hit_range {
                COPY_RECOVERED.fetch_add(1, Ordering::Relaxed);
            }
            // §12.4.1 规则 3：基线上线前必须先证明尺子能分辨"已知更慢"的样本。
            // 带 `bench-pf-load` 构建时，恢复路径上多一段确定性的空循环；
            // 如果 P3 的均值没跟着动，那就是量具坏了，不是代码没变慢。
            #[cfg(feature = "bench-pf-load")]
            crate::tsc::spin(PF_LOAD_ITERATIONS);
            frame.rip = resume;
            return Action::Resume;
        }
        if resume != 0 || expect != 0 || hi != 0 {
            // 有登记、但这次故障不是它：地雷被别人的故障撞上了。计数，判据要能看见它。
            PF_STALE_HITS.fetch_add(1, Ordering::Relaxed);
        }
        // **标签跟着决定走**：同一行现场，ring3 来的叫 `kill`，内核自己的才叫 `fatal`。
        // 之前一律打 `fatal`，结果"越界的用户任务被隔离掉"这条判据在串口上读起来
        // 像内核要挂了——症状与后果不符，排查时会往错的方向走（§9.2 的分级就是为这个）。
        let ring3 = from_user(frame);
        serial::line(if ring3 { "kill" } else { "fatal" },
            format_args!("unexpected #PF rip={:#x} cr2={:#x} err={:#x} cpu_cpl={}", frame.rip, frame.cr2, frame.error_code, if ring3 { 3 } else { 0 }));
    } else {
        serial::line("fatal", format_args!("unexpected vector={} err={:#x} rip={:#x}", frame.vector, frame.error_code, frame.rip));
    }
    if from_user(frame) {
        // 上面那行日志已经留下了现场；这里不停机，改走"杀任务"。
        return Action::Kill;
    }
    dump_frame(frame);
    Action::Fatal
}

/// 一个异常帧占用的字节数（23 个 u64）。`sched` 合成首次运行的帧要用它算栈顶。
pub const TRAP_FRAME_BYTES: usize = core::mem::size_of::<TrapFrame>();

/// 代码/数据段选择子：新任务的首次运行要用同一套，不能各写一个魔数
pub fn kcode_sel() -> u64 {
    SEL_CODE
}

pub fn kdata_sel() -> u64 {
    SEL_DATA as u64
}

/// 用户代码/数据选择子（都带 RPL3）。合成"下到 ring3"的异常帧时用这一对，
/// 不许在别处再写一遍 0x23/0x1B——那两个数是 GDT 排布的函数，写第二处就会漂移。
pub fn ucode_sel() -> u64 {
    SEL_USER_CODE
}

pub fn udata_sel() -> u64 {
    SEL_USER_DATA as u64
}

/// 这个异常帧来自用户态吗（CS 的低两位就是 CPL）。
/// §5.3 R14 第 2 条与 §10.1 入口不变量第 4 条都要这个判断；写成函数是为了只有一处定义。
#[inline]
pub fn from_user(frame: &TrapFrame) -> bool {
    frame.cs & 3 != 0
}

/// 装本 CPU 的 `TSS.rsp0`（ring3→ring0 硬件切过去的那条栈）。
/// 它是**任务级**而不是 CPU 级：M4-1 让每个用户任务带一条自己的内核栈，换入谁就指到谁的栈顶，
/// 于是异常帧天然落在那个任务自己的栈上，`preempt_point` 那道"帧在不在这条栈上"的检查不用改语义。
/// 代价写在明处：每次换入用户任务多一次 TSS 写。真内核会做成"每 CPU 入口栈 + 入口里再切线程栈"。
/// 同一个值还发布给快路径（`SYSCALL` 不查 TSS），所以这里是一个写入点喂两个消费者，
/// 判据仍交叉核对（`fast_area_of` vs `tss_offsets`）。
/// **写之前本 CPU 的 IF 必须是 0**，否则一次中断可能读到改了一半的 rsp0。
pub fn set_rsp0(slot: usize, va: u64) {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return;
    }
    // SAFETY: 见 TablesSlot——本 CPU 写自己那一槽的 TSS
    let t = unsafe { &mut *TABLES[slot].0.get() };
    // SAFETY: packed 字段必须按不可对齐的方式写（见 `Tss` 的注释：这个字段落在
    // 偏移 4，而 `u64` 的自然对齐是 8，引用与直接赋值都不允许）
    unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.rsp0), va) };
    // 同一个值发布给快路径：`SYSCALL` 不查 TSS，硬件不给它换栈。
    // **一个写入点喂两个消费者**，所以"rsp0 与快路径不同源"这种错法在结构上不会出现；
    // 判据仍然交叉核对（`fast_area_of` vs `tss_offsets`），因为"同一个函数写"不等于"同一个值"。
    if slot < crate::arch::x86_64::cpu::MAX_CPUS {
        // SAFETY: 本 CPU 写自己那一格
        unsafe {
            (*FAST_AREAS[slot].0.get()).kstack_top = va;
        }
    }
}

/// 本 CPU 当前的 rsp0（0 = 还没装，那时任何 ring3 陷入都会 #DF）。
pub fn rsp0_of(slot: usize) -> u64 {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return 0;
    }
    // 走 `tss_offsets`：读的是**架构位置**上那 8 个字节，不是"我以为的字段"
    tss_offsets(slot).map_or(0, |(rsp0, _, _)| rsp0)
}

/// GDT 第 `i` 项的原始 8 字节。
///
/// 为什么用例要直接看这 8 个字节：M4-1 那条 #GP 的现场是"选择子完全正确、
/// 描述符却是错的"（用户数据段漏了 S 位 ⇒ 整个条目变成系统描述符）。
/// 那种故障只有不触发异常的一条路能提前抓到，而触发异常的那条把它报成
/// 一个抹掉 RPL 的选择子号码（0x1b → 0x18），指不到真正错的那一位。
pub fn gdt_entry(slot: usize, i: usize) -> Option<u64> {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS || i >= GDT_QWORDS {
        return None;
    }
    // SAFETY: 只读，且读的是自己那一槽
    Some(unsafe { (*TABLES[slot].0.get()).gdt[i] })
}

/// `bench-pf-load` 注入的确定性负载：20 万次不依赖内存的加法/或运算。
/// 数值选择的原则不是"像真实驱动"，而是**必须压过最紧的那次故障**：
/// 实测不带负载时 P3 的 min≈1.2k 周期（max≈21.6 万，那是冷 TLB/页表走的全价），
/// 所以要证明尺子能动，看的是 **min**，负载量级必须明显大于 min 本身。
#[cfg(feature = "bench-pf-load")]
pub const PF_LOAD_ITERATIONS: usize = 200_000;

/// asm 侧的入口垫片。
///
/// # Safety 契约（由 `isr_common` 保证）
/// `frame` 必须指向当前异常栈上真实的完整帧，且此后 `iretq` 会用同一份内容；
/// 因此本函数**只能**由异常桩调用，不能在 Rust 里构造假帧传进来。
#[no_mangle]
pub unsafe extern "C" fn aurora_trap_entry(frame: &mut TrapFrame) {
    // P3/P5 的下界读数（新边界见 `isr_common` 出口那段的注释：不含异常桩的寄存器保存）。
    // 取完就存进本 CPU 的行，致命出口那条路径要从这里回看。
    let cpu = crate::arch::x86_64::cpu::self_slot();
    let t0 = crate::tsc::now();
    mark_entry(cpu, t0);
    // 向量号在读数的同一时刻记下来，两条出口路径才都有读数（见 `note_last_vec`）。
    note_last_vec(cpu, frame.vector);
    match dispatch(frame) {
        Action::Fatal => crate::exit_fatal_from_exception(frame),
        // 用户任务的故障：标 Done + 把它停在自己的死循环里。
        // **不停机**——这条分支存在的全部意义就是"一个用户程序的错不变成整台机器的错"。
        Action::Kill => (crate::hooks::sched().park_current)(frame),
        // `SYS_EXIT`：只把"结束"这个动作登记下来，**不在这个上下文里释放任何东西**
        Action::Exit => (crate::hooks::sched().exit_current)(cpu),
        Action::Resume => {}
    }
    // 抢占点：此刻 frame 就压在**被中断任务自己的栈**上，所以它就是续跑点。
    // 若发生切换，下面这行不会返回（见 sched::preempt_point）。
    // SAFETY: 见 preempt_point 的契约——frame 必须是本任务栈上真实的异常帧，
    // 而它正是上面 `mov rdi, rsp` 交给我们的那个地址。
    (crate::hooks::sched().preempt_point)(core::ptr::addr_of_mut!(*frame) as u64, cpu);
    // 换出过就不会走到这里。快路径的 rflags 要被 `sysretq` 从 r11 装回去，而那条出口
    // 不经过 `if_patch` —— IF 属于 CPU（ADR-021），在这里按本 CPU 的窗口写。
    if frame.vector == VEC_SYSCALL_FAST {
        fast_fix_if(frame, cpu);
    }
    // 走到这里就说明**没有**换人，出口记账归本函数；换出去的那次由 preempt_point 补记。
    // 两条路径各记一次、且只记一次——这条不变量由用例数出来（P5 样本数 == 驱动侧计数）。
    record_sample(cpu, frame.vector, crate::tsc::now().wrapping_sub(t0));
}

/// 触发一次受控 #PF。
///
/// 返回 `Some(1)` 表示异常确实被取到并成功恢复；返回 `None` 表示没触发
/// （地址其实是映射着的 => 探针失效）。**故意把“没触发”做成可区分的结果**，
/// 否则这条用例会永远绿。
///
/// SAFETY: `addr` 必须是已确认未映射的规范地址，由调用方按内存映射校验。
pub fn probe_page_fault(addr: u64) -> Option<u64> {
    PF_RESUME.store(0, Ordering::Relaxed);
    PF_EXPECT.store(0, Ordering::Relaxed);
    let before = PF_TAKEN.load(Ordering::Relaxed);
    let ret: u64;
    // SAFETY: pf_probe 只做一个字节读 + 一次返回；入参走 rdi，返回值走 rax
    //（注意：返回值在 rax，不能用 inlateout("rdi")，否则会把探针地址当成返回值）
    unsafe {
        core::arch::asm!("call pf_probe", in("rdi") addr, lateout("rax") ret, options(preserves_flags));
    }
    // **走到这里就必须把两条登记清掉**。故障路径已经由分发里的 `swap(0)` 清过，
    // 这条收尾管的是"没故障"那一路：访到了映射着的页 => 探针失效，
    // 但登记还在 .data 里，留着就是下一次无关故障的劫持目标（M4-1 实测到的事故）。
    PF_RESUME.store(0, Ordering::Relaxed);
    PF_EXPECT.store(0, Ordering::Relaxed);
    (PF_TAKEN.load(Ordering::Relaxed) > before).then_some(ret)
}

/// 探针登记是否还留着（用例用它证明"每次探针回来都是干净的"）。
pub fn probe_registers_clear() -> bool {
    PF_RESUME.load(Ordering::Relaxed) == 0
        && PF_EXPECT.load(Ordering::Relaxed) == 0
        && PF_LO.load(Ordering::Relaxed) == 0
        && PF_HI.load(Ordering::Relaxed) == 0
}

pub fn dump_frame(f: &TrapFrame) {
    serial::line("cpu", format_args!("vec={} err={:#x} rip={:#x} cs={:#x} rflags={:#x} rsp={:#x} ss={:#x}", f.vector, f.error_code, f.rip, f.cs, f.rflags, f.rsp, f.ss));
    // 第二行原来把 `f.rsp` 标成了 `rsp0=`——那是量具在说谎：读的人会把"被打断的 rsp"
    // 当成"TSS.rsp0"，而 M4-1 的排查正好被它带过一次（rsp 与 rsp0 相等的假象让我
    // 以为故障发生在 ring3→ring0 的换栈瞬间）。这里把两者分开、各自给真值。
    serial::line("cpu", format_args!("cr2={:#x} rax={:#x} rbx={:#x} rbp={:#x} pf_stale_hits={}", f.cr2, f.rax, f.rbx, f.rbp, PF_STALE_HITS.load(Ordering::Relaxed)));
    let (smep, smap) = crate::arch::x86_64::cpu::user_protections_active();
    serial::line("cpu", format_args!("rsp0={:#x} from_user={} smep={} smap={} cr4={:#x}", rsp0_of(crate::arch::x86_64::cpu::self_slot()), from_user(f), smep, smap, crate::arch::x86_64::cpu::cr4()));
}

pub fn halt_forever() -> ! {
    loop {
        // SAFETY: cli+hlt 是停机惯用法。asm! 没有输出，LLVM 不会把它当纯表达式删掉
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

// ---------------------------------------------------------------- SYSCALL 快路径（ADR-025）

/// 快路径样本的"向量号"。`SYSCALL` 不查 IDT、硬件不压帧，所以这一格由我们自己标
/// —— 它就是"这条样本从哪个入口来"的记录，P7 表靠它把两条入口分开数。
pub const VEC_SYSCALL_FAST: u64 = 0x180;

/// `swapgs` 之后 `gs:[...]` 指着本 CPU 的这一格。偏移被 asm 直接写死，
/// 所以这里有编译期断言 + 一个运行时读回函数（同 `Tss` 那条纪律：按架构偏移摆字段，
/// 并且取证读的是位置而不是字段名）。
#[repr(C)]
pub struct FastArea {
    /// 换入用户任务时装进 `TSS.rsp0` 的同一个值：`SYSCALL` 不换栈，得自己找栈。
    pub kstack_top: u64,
    pub slot: u64,
    /// SYSCALL 把返回 rip 放在 rcx、rflags 放在 r11，rsp 又是用户控制的。
    pub rip: u64,
    pub nr: u64,
    pub user_rsp: u64,
    /// 造出来的帧的基址（出口要从这里取 rip/rflags/返回值）。
    pub frame_base: u64,
    pub _pad: [u64; 2],
}
pub const FA_KSTACK: usize = 0;
pub const FA_SLOT: usize = 8;
pub const FA_RIP: usize = 16;
pub const FA_NR: usize = 24;
pub const FA_USER_RSP: usize = 32;
pub const FA_FRAME: usize = 40;
const _: () = assert!(core::mem::offset_of!(FastArea, kstack_top) == FA_KSTACK);
const _: () = assert!(core::mem::offset_of!(FastArea, slot) == FA_SLOT);
const _: () = assert!(core::mem::offset_of!(FastArea, rip) == FA_RIP);
const _: () = assert!(core::mem::offset_of!(FastArea, nr) == FA_NR);
const _: () = assert!(core::mem::offset_of!(FastArea, user_rsp) == FA_USER_RSP);
const _: () = assert!(core::mem::offset_of!(FastArea, frame_base) == FA_FRAME);
const _: () = assert!(core::mem::size_of::<FastArea>() == 64);

#[repr(C, align(64))]
struct FastSlotCell(core::cell::UnsafeCell<FastArea>);
// SAFETY: 每个 CPU 只写自己那一格（`slot` 由 BSP 分配且互不重复，见 cpu.rs 那条），
// 写发生在装机或换入用户任务时，本 CPU IF=0。
unsafe impl Sync for FastSlotCell {}
static FAST_AREAS: [FastSlotCell; crate::arch::x86_64::cpu::MAX_CPUS] = [const {
    FastSlotCell(core::cell::UnsafeCell::new(FastArea {
        kstack_top: 0,
        slot: 0,
        rip: 0,
        nr: 0,
        user_rsp: 0,
        frame_base: 0,
        _pad: [0; 2],
    }))
}; crate::arch::x86_64::cpu::MAX_CPUS];

static FAST_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// 装机时读回的 EFER/STAR/LSTAR 值，供用例核对"写了并且生效了"。
static FAST_READBACK: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

pub fn fastpath_on() -> bool {
    FAST_ON.load(Ordering::Acquire)
}

/// (kstack_top, slot)：判据用它交叉核对"rsp0 与快路径用的是不是同一个值"。
pub fn fast_area_of(slot: usize) -> Option<(u64, u64)> {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS {
        return None;
    }
    // SAFETY: 只读本 CPU 那一格的快照；跨槽读只是观测（同 `rsp0_of`）
    let a = unsafe { &*FAST_AREAS[slot].0.get() };
    Some((a.kstack_top, a.slot))
}

pub fn fast_readback() -> (u64, u64, u64) {
    (
        FAST_READBACK[0].load(Ordering::Relaxed),
        FAST_READBACK[1].load(Ordering::Relaxed),
        FAST_READBACK[2].load(Ordering::Relaxed),
    )
}

/// 每台 CPU 装一次快路径。CPUID 说不支持就**什么都不装**并返回 false：
/// `int 0x80` 那条路还在，快路径是可选特性，不是启动前提。
/// 返回值是"装了并且读回确认了"。
pub fn install_fastpath(slot: usize) -> bool {
    if slot >= crate::arch::x86_64::cpu::MAX_CPUS || !crate::arch::x86_64::cpuid::detect().syscall {
        return false;
    }
    extern "C" {
        fn syscall_entry();
    }
    let addr = syscall_entry as usize as u64;
    // STAR：[47:32]=SYSCALL 的 CS（内核代码 0x08）；[63:48]=SYSRET 的选择子基值（0x10）
    // ⇒ CS = 0x10+0x10|3 = 0x23（用户代码）、SS = 0x10+0x08|3 = 0x1B（用户数据）
    let star: u64 = (0x0008u64 << 32) | (0x0010u64 << 48);
    // SFMASK：TF|IF|DF|RF|AC。关 IF 由这一位给出（这条入口没有中断门替我们关）
    let sfmask: u64 = 0x100 | 0x200 | 0x400 | 0x10000 | 0x40000;
    // EFER.SCE（bit0）不打开的话 `syscall` 就是 #UD；NXE 之类保持原样
    let efer_before = crate::arch::x86_64::cpu::rdmsr(0xC000_0080);
    let efer = crate::arch::x86_64::cpu::wrmsr(0xC000_0080, efer_before | 1);
    crate::arch::x86_64::cpu::wrmsr(crate::arch::x86_64::cpu::MSR_STAR, star);
    crate::arch::x86_64::cpu::wrmsr(crate::arch::x86_64::cpu::MSR_LSTAR, addr);
    crate::arch::x86_64::cpu::wrmsr(crate::arch::x86_64::cpu::MSR_SFMASK, sfmask);
    // GS 的两边：用户侧清零，内核侧指向本 CPU 的那格
    crate::arch::x86_64::cpu::wrmsr(crate::arch::x86_64::cpu::MSR_GS_BASE, 0);
    let area = FAST_AREAS[slot].0.get() as u64;
    let gs_seen = crate::arch::x86_64::cpu::wrmsr(crate::arch::x86_64::cpu::MSR_KERNEL_GS_BASE, area);
    // SAFETY: 本 CPU 写自己那一格
    unsafe {
        (*FAST_AREAS[slot].0.get()).slot = slot as u64;
    }
    let (s_seen, l_seen) = (crate::arch::x86_64::cpu::rdmsr(crate::arch::x86_64::cpu::MSR_STAR), crate::arch::x86_64::cpu::rdmsr(crate::arch::x86_64::cpu::MSR_LSTAR));
    FAST_READBACK[0].store(efer, Ordering::Relaxed);
    FAST_READBACK[1].store(s_seen, Ordering::Relaxed);
    FAST_READBACK[2].store(l_seen, Ordering::Relaxed);
    let ok = efer & 1 != 0 && s_seen == star && l_seen == addr && gs_seen == area;
    if ok {
        FAST_ON.store(true, Ordering::Release);
    }
    serial::line(
        if ok { "info" } else { "fatal" },
        format_args!("fastpath cpu{slot}: efer={efer:#x} star={s_seen:#x} lstar={l_seen:#x} gs={gs_seen:#x}(期望 {area:#x}) on={ok}"),
    );
    ok
}

/// 快路径出口的 IF：`sysretq` 从 r11 装 rflags，而它不经过 `if_patch`（那条只打在换入上）。
/// ADR-021"IF 属于 CPU"在这条路径上的实现点，写成一句可核对的话放在 ADR-025。
pub fn fast_fix_if(frame: &mut TrapFrame, cpu: usize) {
    let on = crate::arch::x86_64::apic::interrupts_enabled(cpu);
    frame.rflags = if on { frame.rflags | 0x200 } else { frame.rflags & !0x200 };
}

// ------------------------------------------------------------------ asm 部分

core::arch::global_asm!(
    r#"
    .text
    .code64

    // 无错误码的向量：CPU 没压错误码，压 0 占位，再压向量号 ——
    // 这样两条路径在 isr_common 处的栈布局完全一致（vec, error_code, rip, cs, rflags, ...）
    .macro STUB_NOERR n
    .global isr_stub_\n
isr_stub_\n:
    push 0
    push \n
    jmp isr_common
    .endm

    // 有错误码的向量：CPU 已压错误码，只压向量号
    .macro STUB_ERR n
    .global isr_stub_\n
isr_stub_\n:
    push \n
    jmp isr_common
    .endm

    STUB_NOERR 0
    STUB_NOERR 1
    STUB_NOERR 2
    STUB_NOERR 3
    STUB_NOERR 4
    STUB_NOERR 5
    STUB_NOERR 6
    STUB_NOERR 7
    STUB_ERR   8
    STUB_NOERR 9
    STUB_ERR   10
    STUB_ERR   11
    STUB_ERR   12
    STUB_ERR   13
    STUB_ERR   14
    STUB_NOERR 15
    STUB_NOERR 16
    STUB_ERR   17
    STUB_NOERR 18
    STUB_NOERR 19
    STUB_NOERR 20
    STUB_ERR   21
    STUB_NOERR 22
    STUB_NOERR 23
    STUB_NOERR 24
    STUB_NOERR 25
    STUB_NOERR 26
    STUB_NOERR 27
    STUB_NOERR 28
    STUB_NOERR 29
    STUB_NOERR 30
    STUB_NOERR 31
    STUB_NOERR 32
    STUB_NOERR 33
    STUB_NOERR 34
    STUB_NOERR 35
    STUB_NOERR 36
    STUB_NOERR 37
    STUB_NOERR 38
    STUB_NOERR 39
    STUB_NOERR 40
    STUB_NOERR 41
    STUB_NOERR 42
    STUB_NOERR 43
    STUB_NOERR 44
    STUB_NOERR 45
    STUB_NOERR 46
    STUB_NOERR 47
    // 每 CPU 本地定时器（0xF1）：**M3b-2b 起它走正常的异常帧路径**。
    // 之前它有一条不建帧的快路，那是"AP 不跑调度器"的配套：抢占的唯一续跑格式就是
    // 异常帧（本模块头第 1 条），不建帧就永远不可能在 AP 上换人。现在 AP 要跑自己的
    // 队列，所以这条中断必须和其他中断一样建帧、进 `isr_common`、出到抢占点。
    // P5 表也已经按 CPU 分行，所以 AP 的样本不会再污染 BSP 的那把尺子（这正是当初
    // 用快路径回避的问题，现在用"分表"解决，而不是用"不记账"回避）。
    STUB_NOERR 240
    STUB_NOERR 241
    // ring3 发起系统调用的门（int 0x80）。走 isr_common：建异常帧、进 Rust 分发。
    // 它与别的向量有一处不同——**门是 DPL3**（见 `idt_gate`），所以 ring3 进得来、
    // ring0 也进得来（自己 int 自己 = 内核内的同一条路径，用例用它测嵌套进入）。
    STUB_NOERR 128

    // "不该出现的向量"：48..254 共用一条桩。它们仍然压一个向量号占位（用 48），
    // 真实身份由 apic 侧计数；共用是为了不把 207 个符号塞进镜像，
    // 而**不是**因为"这些向量不会来"——它们来了必须计数并 EOI，不能变成静默的 #GP。
isr_stub_unexpected:
    push 48
    jmp isr_common

    // spurious（SVR 的向量 0xFF）：计数，且**不发 EOI**（见 VEC_SPURIOUS 的注释）
isr_stub_spurious:
    push 255
    jmp isr_common

    // 两条"快路径"中断（AP 本地 tick、TLB shootdown）共用的寄存器组。
    // 用宏而不是复制两遍：15 个 GPR 少存哪一个，表现都是"某个任务的某个寄存器在
    // 中断之后变成别的值"——那种故障在现场完全看不出来，只会在几百轮之后变成一次坏数据。
    .macro FAST_PROLOG
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rbp, rsp
    and rsp, -16
    cld
    .endm

    .macro FAST_EPILOG
    mov rsp, rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq
    .endm

    // TLB shootdown（§6.6，向量 0xF2）：本 CPU 收到请求 → 按 mm 公布的 VA 做一次
    // invlpg → 回执计数 +1 → EOI。
    // 这条路径**不许**拿任何锁：请求方正持有 VMM(20) 锁等回执，这里再取同一把锁
    // 就是跨 CPU 死锁（而 §7.1 的重入检测只看令牌，令牌是别的 CPU，判不出来）。
    .global isr_stub_shootdown
isr_stub_shootdown:
    FAST_PROLOG
    call aurora_shootdown
    FAST_EPILOG

    .align 16
isr_common:
    // 下界读数在 Rust 垫片里（见下面出口的说明：这两把尺子已经整段搬到 Rust）。
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    // CR2 必须在进 Rust 之前取走：处理路径里任何一次嵌套 #PF 都会覆盖它
    mov rax, cr2
    push rax
    mov rdi, rsp
    // 栈对齐修正。ring0->ring0 的 #PF 到这里时，15 个 GPR + CR2 共 128 字节，
    // 而起异常时 rsp 在函数内部恒为 ≡8 (mod 16)，于是 call 之前 rsp ≡ 8 —— 违反
    // SysV“call 指令处 rsp ≡ 0”。被调函数若用到 SSE/推送偶数个寄存器就会踩坏栈或
    // 直接 #GP，表现是启动期三重故障，极难归因。这里把帧指针留一份再向下对齐，
    // 出口再用它还原，不参与 iretq 的字段。
    mov rbp, rsp
    and rsp, -16
    cld
    call aurora_trap_entry
    mov rsp, rbp
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    // 出口不做记账（M3b-2b）：记账整段搬到 `aurora_trap_entry`。理由是 per-CPU——
    // asm 里要按 CPU 索引这张表就得先知道"我是哪个 CPU"，而读 LAPIC 寄存器是 UC- MMIO（≈600 周期，
    // ADR-024），把槽位塞进 `IA32_TSC_AUX` 又等于给内核新增一条必需 CPU 特性。
    // Rust 侧本来就有 `cpu::self_slot()` 这条已付过代价的路 ⇒ 表放 Rust 里按槽位索引，
    // asm 只保留"存/取现场 + iretq"。**槽位在入口处读一次就往下传**，不许出现在被测区间内部。
    // P3/P5 的边界因此移动（现在是"进 Rust 垫片到出垫片"，桩那 15+1 次 push/pop 在测量之外）：
    // 新旧数字不可比，写进 §12.4.1；净变化不做估算，看 bench 的同构建对照。
    add rsp, 16
    iretq

    // 换段选择子：retfq 之后 CS 才是新 GDT 里的 0x08，之前任何取指都可能三重故障
    .global flush_segments
flush_segments:
    push rdi
    lea rax, [rip + .Lseg_loaded]
    push rax
    retfq
.Lseg_loaded:
    mov ds, si
    mov es, si
    mov ss, si
    mov fs, si
    mov gs, si
    ret

    // 受控 #PF 探针：先登记恢复地址**与预期故障的 VA**，再读 [rdi] 一字节；
    // 异常桩把 RIP 改成 .Lpf_resume，于是 iretq 后从这里继续，返回 1。
    // 两条登记必须成对（见 PF_EXPECT 的注释）：只登记地址的话，"探针没故障"这一条
    // 路径会把地址留在 .data 里，成为下一次无关故障的劫持目标。
    .align 16
    .global pf_probe
pf_probe:
    lea rax, [rip + .Lpf_resume]
    mov qword ptr [rip + PF_RESUME], rax
    mov qword ptr [rip + PF_EXPECT], rdi
    movzx eax, byte ptr [rdi]
.Lpf_resume:
    mov rax, 1
    ret

    .section .rodata
    .align 8
    .global isr_table
isr_table:
    .quad isr_stub_0
    .quad isr_stub_1
    .quad isr_stub_2
    .quad isr_stub_3
    .quad isr_stub_4
    .quad isr_stub_5
    .quad isr_stub_6
    .quad isr_stub_7
    .quad isr_stub_8
    .quad isr_stub_9
    .quad isr_stub_10
    .quad isr_stub_11
    .quad isr_stub_12
    .quad isr_stub_13
    .quad isr_stub_14
    .quad isr_stub_15
    .quad isr_stub_16
    .quad isr_stub_17
    .quad isr_stub_18
    .quad isr_stub_19
    .quad isr_stub_20
    .quad isr_stub_21
    .quad isr_stub_22
    .quad isr_stub_23
    .quad isr_stub_24
    .quad isr_stub_25
    .quad isr_stub_26
    .quad isr_stub_27
    .quad isr_stub_28
    .quad isr_stub_29
    .quad isr_stub_30
    .quad isr_stub_31
    .quad isr_stub_32
    .quad isr_stub_33
    .quad isr_stub_34
    .quad isr_stub_35
    .quad isr_stub_36
    .quad isr_stub_37
    .quad isr_stub_38
    .quad isr_stub_39
    .quad isr_stub_40
    .quad isr_stub_41
    .quad isr_stub_42
    .quad isr_stub_43
    .quad isr_stub_44
    .quad isr_stub_45
    .quad isr_stub_46
    .quad isr_stub_47
    // 48..127：共用"不该出现的向量"桩
    .rept 80
    .quad isr_stub_unexpected
    .endr
    // 128：ring3 的系统调用门（M4-1）
    .quad isr_stub_128
    // 129..239：又回到共用桩
    .rept 111
    .quad isr_stub_unexpected
    .endr
    // 240：主动让出/重调度（ADR-049）。建帧，理由与 241 同：不建帧就换不了人。
    .quad isr_stub_240
    // 241：每 CPU 本地定时器（M3b-2b 起走异常帧）
    .quad isr_stub_241
    // 242..254：仍然共用意外桩。242 是 shootdown，但 IDT 里那一格由 Rust 侧
    // 换成 `isr_stub_shootdown`（见 init_cpu_tables），这张表的这一项不会被用上。
    .rept 13
    .quad isr_stub_unexpected
    .endr
    .quad isr_stub_spurious

    // 给 Rust 侧取 shootdown 桩的地址。不塞进 isr_table 是因为那张表的下标就是向量号，
    // 而 isr_table[242] 已经被 .rept 填成了 unexpected 桩（它压的向量号是 48）；
    // 改它会牵动 handler_count_distinct 那条判据的语义。
    .align 8
    .global isr_shootdown_gate
isr_shootdown_gate:
    .quad isr_stub_shootdown

    // SYSCALL 快路径入口（ADR-025）。窗口 = SYSCALL 到 swapgs 之间，所以第一条就是 swapgs，
    // 它不访存、不碰段寄存器、不读用户内存。本内核零处依赖 gs:，因此 NMI 落在窗口里
    // 也拿不到"错误但被使用"的 GS —— 这条前提一旦破了（哪天有代码在非快路径里读 gs:），
    // 就必须回头补 paranoid entry 的影子栈，见 ADR-025 的论证。
    //
    // 不借任何寄存器：rcx/rax/rsp 三个值经 gs 暂存，其余按 isr_common 的顺序原样压帧，
    // 所以用户程序的 rbx/rbp/r12-r15 与全部参数都不被偷偷破坏（§10.2 只承诺破坏 rcx/r11/rax）。
    .global syscall_entry
syscall_entry:
    swapgs
    mov qword ptr gs:[16], rcx      // 返回 rip
    mov qword ptr gs:[24], rax      // 调用号
    mov qword ptr gs:[32], rsp      // 用户 rsp
    mov rax, qword ptr gs:[0]       // 本 CPU 的用户任务内核栈顶
    test rax, rax
    jz .Lsyscall_no_kstack          // 没换入过用户任务就不该有人在这打 syscall
    mov rsp, rax
    push 0x1b                       // ss  = 用户数据
    push qword ptr gs:[32]          // rsp = 用户
    push r11                        // rflags（用户的那份）
    push 0x23                       // cs  = 用户代码
    push qword ptr gs:[16]          // rip
    push 0                          // error_code
    push 0x180                      // vector = VEC_SYSCALL_FAST（硬件不给）
    push qword ptr gs:[24]          // rax = 调用号
    push rbx
    push qword ptr gs:[16]          // rcx = 返回 rip：这就是 SYSCALL 的 ABI
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rax, cr2
    push rax                        // cr2：与异常路径同一条纪律，进 Rust 之前取走
    mov rdi, rsp
    mov rbp, rsp
    mov qword ptr gs:[40], rbp      // 出口要从这里读 rip/rflags/返回值
    and rsp, -16
    cld
    call aurora_trap_entry
    mov rsp, rbp
    mov rbp, qword ptr gs:[40]
    mov rcx, qword ptr [rbp + 144]  // rip（被杀/被改过也照新值回）
    mov r11, qword ptr [rbp + 160]  // rflags（IF 已由 Rust 按本 CPU 的窗口写好）
    mov rax, qword ptr [rbp + 120]  // 返回值
    mov rbx, qword ptr [rbp + 112]
    mov rdx, qword ptr [rbp + 96]
    mov rsi, qword ptr [rbp + 88]
    mov rdi, qword ptr [rbp + 80]
    mov r8,  qword ptr [rbp + 64]
    mov r9,  qword ptr [rbp + 56]
    mov r10, qword ptr [rbp + 48]
    mov r12, qword ptr [rbp + 32]
    mov r13, qword ptr [rbp + 24]
    mov r14, qword ptr [rbp + 16]
    mov r15, qword ptr [rbp + 8]
    mov rsp, qword ptr [rbp + 168]  // 用户 rsp
    mov rbp, qword ptr [rbp + 72]   // 用户 rbp：base 用完了，最后一步
    swapgs
    sysretq
.Lsyscall_no_kstack:
    // 不变量破了：内核栈还没装就收到快路径调用。继续往下会写到地址 0（ring0 的 #PF，
    // 归因成"退出路径自己写坏了"），所以在这里留一条最响的信号。
    ud2
"#
);

/// 供 main.rs 打印异常桩覆盖范围用（证明 32 个门都指到了不同入口）
pub fn handler_count_distinct() -> usize {
    let mut seen = [0u64; 32];
    for i in 0..32 {
        seen[i] = unsafe { isr_table[i] };
    }
    let mut n = 0;
    for i in 0..32 {
        if !seen[..i].contains(&seen[i]) {
            n += 1;
        }
    }
    n
}
