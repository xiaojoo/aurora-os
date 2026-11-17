//! A3：外部 ELF 的**装载与启动**编排层（ADR-131）。
//!
//! 把一条链路收进一个函数：22/25 号读文件 → [`crate::elf`] 解析 + 逐段 VMO →
//! 14 号铺进子 AS → 栈页 / SI 页 → 11/15/16 启动 → 17 号取退出码。
//!
//! **这一层不认"命令"**：路径怎么来（argv、`PATH` 搜索、内置表）是调用方的事，
//! 本模块只回答"给一条卷上路径，能不能把它跑起来、退出码是多少"。
//! 内核侧机制一个字没动：全部用既有号（22/25/12/13/14/11/15/16/17）。
//!
//! 缓冲区全部静态（4 KiB 头块/顺序读块）；用户态单线程，没有并发窗口。

use crate::elf::{self, Image, PAGE};
use crate::{
    file_open, file_read, file_stat, handle_close, handle_dup, process_create, process_start,
    process_wait, thread_create, vmo_create, vmo_map, vmo_write, Handle, RTError, RIGHT_READ,
    RIGHT_TRANSFER, RIGHT_WRITE, ROLE_LOG,
};

/// 顺序读块大小（也是头块大小）：4 KiB 够放 e_ehdr(64) + 16 条 phdr(56)。
pub const CHUNK: usize = 4096;

/// SI 页里描述表的起始偏移（ADR-075 / ADR-130 的同一组数）。
const SI_OFF_HANDLES: usize = 24;
/// 一条描述的字节数。
const SI_DESC_BYTES: usize = 16;
/// 头 24 字节（魔数/ABI 版本/nhandles）。
const SI_HDR: usize = SI_OFF_HANDLES;
/// `SI_MAGIC`（"AURO"）。
const SI_MAGIC: [u8; 4] = [0x4F, 0x52, 0x55, 0x41];
// ABI minor **取运行期**的值（`abi_info` 的高 8 位）：内核 16 号按 `minor == ABI_MINOR`
// 逐位相等校验，写死的 12 在 ABI 0.13/0.14 上会被拒成 -1（合并时实测，与 execprobe 同因）。

/// 静态读块。**为什么放在库里而不是调用方传**：调用方（shell）的栈只有一页，
/// 4 KiB 局部数组会把栈顶穿出去（execprobe 实测过 #PF `cr2=0x...4ff8 err=0x6`）；
/// 也省得每个调用方各写一份 `static mut` + `addr_of!`。单线程用户程序，无并发窗口。
static mut CHUNK_BUF: [u8; CHUNK] = [0u8; CHUNK];

/// 取静态读块。**唯一借出方**是本模块的顺序读循环。
///
/// # Safety（内部）
/// 由本模块独占：`load` 在同一时刻只可能被同一个单线程程序调用一次。
fn chunk() -> &'static mut [u8] {
    let p: *mut u8;
    // SAFETY: `lea` 只算地址不访存；取址走 **RIP 相对**，因为 `.bss` 在 4 GiB 之上，
    // `addr_of_mut!` 会退化成 `R_X86_64_32S` 绝对重定位（实测：shell 链接 runtime 时
    // 三处 `references section '.bss....CHUNK_BUF'` out of range）。
    // 切片本身由本模块独占（见上面 CHUNK_BUF 的注释）。
    unsafe {
        core::arch::asm!(
            "lea {}, [rip + {sym}]",
            out(reg) p,
            sym = sym CHUNK_BUF,
            options(nomem, nostack, preserves_flags)
        );
        core::slice::from_raw_parts_mut(p, CHUNK)
    }
}

/// 往 `b[off..off+4]` 写一个小端 u32（越界静默不写下标——缓冲区都是定长常量）。
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    let mut i = 0usize;
    while i < 4 {
        match b.get_mut(off + i) {
            Some(s) => *s = (v >> (i * 8)) as u8,
            None => return,
        }
        i += 1;
    }
}

/// 往 `b[off..off+8]` 写一个小端 u64。
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    let mut i = 0usize;
    while i < 8 {
        match b.get_mut(off + i) {
            Some(s) => *s = (v >> (i * 8)) as u8,
            None => return,
        }
        i += 1;
    }
}

/// 一份装载好的镜像：段表 + 每段的 VMO 句柄（父暂持，16 号 `adopt_asmaps` 转给子线程）。
pub struct Loaded {
    /// 已校验的 ELF 段表与入口/栈顶。
    pub img: Image,
    /// 每段一个 VMO（`img.nseg` 个有效）。
    pub segs: [Handle; elf::MAX_SEGS],
    /// 实际读到的文件字节数（判据用：与 25 号 stat 的 size 对账）。
    pub bytes: u64,
}

/// 读卷上一个 ELF 并装进 VMO（**不启动**）。
///
/// 无 24 号 seek 的构建也能用：顺序读块 + 按段过滤（[`elf::write_chunk`]）。
pub fn load(path: &[u8]) -> Result<Loaded, RTError> {
    let fh = file_open(path, 0)?;
    let st = match file_stat(fh) {
        Ok(s) => s,
        Err(e) => {
            let _ = handle_close(fh);
            return Err(e);
        }
    };
    let buf = chunk();
    let n = match file_read(fh, buf) {
        Ok(n) => n,
        Err(e) => {
            let _ = handle_close(fh);
            return Err(e);
        }
    };
    // 解析（段界校验按**整文件**长度，头块只是文件的一段）。
    let img = {
        let head = match buf.get(..n) {
            Some(h) => h,
            None => {
                let _ = handle_close(fh);
                return Err(RTError::INVALID);
            }
        };
        match elf::parse(head, st.size() as u64) {
            Ok(i) => i,
            Err(e) => {
                let _ = handle_close(fh);
                return Err(e);
            }
        }
    };
    let (segs, _) = match elf::create_seg_vmos(&img) {
        Ok(v) => v,
        Err(e) => {
            let _ = handle_close(fh);
            return Err(e);
        }
    };
    // 头块里属于段的内容先写一遍，再顺序读剩余块。
    {
        let head = match buf.get(..n) {
            Some(h) => h,
            None => {
                let _ = handle_close(fh);
                return Err(RTError::INVALID);
            }
        };
        if let Err(e) = elf::write_chunk(&img, &segs, head, 0) {
            let _ = handle_close(fh);
            return Err(e);
        }
    }
    let mut off = n as u64;
    let mut total = n as u64;
    loop {
        let k = match file_read(fh, chunk()) {
            Ok(k) => k,
            Err(e) => {
                let _ = handle_close(fh);
                return Err(e);
            }
        };
        if k == 0 {
            break;
        }
        let part = match chunk().get(..k) {
            Some(p) => p,
            None => {
                let _ = handle_close(fh);
                return Err(RTError::INVALID);
            }
        };
        if let Err(e) = elf::write_chunk(&img, &segs, part, off) {
            let _ = handle_close(fh);
            return Err(e);
        }
        off += k as u64;
        total += k as u64;
    }
    let _ = handle_close(fh);
    Ok(Loaded { img, segs, bytes: total })
}

/// 把装好的镜像启动成一个新进程。返回 `(proc, thread)` 句柄（等待用 proc）。
///
/// `console` 是调用方自己的控制台句柄：内部分配一个**副本**（带 `RIGHT_TRANSFER`）
/// 以 `ROLE_LOG` 转移给子进程——既有产物（hello/shell）认的就是这个角色号。
pub fn launch(l: &Loaded, console: Handle, job: Handle, argv0: &[u8]) -> Result<Handle, RTError> {
    let proc = process_create(job)?;
    // 逐段映射（14 号；VA 对账在 map_segs 里，内核给了别的地址就明确拒）。
    elf::map_segs(proc, &l.img, &l.segs)?;
    // 栈：一页，放在镜像末尾之后留 4 页空隙（与 execprobe 的布局同一条算式）。
    let stack_va = (l.img.stack_top - PAGE) + 4 * PAGE;
    let stack_top = stack_va + PAGE;
    let stack_vmo = vmo_create(1)?;
    vmo_map(proc, stack_vmo, stack_va, true, false)?;
    // SI 页：头 24 字节 + 一条 ROLE_LOG 描述（控制台的副本）。
    let si = vmo_create(1)?;
    let con_dup = handle_dup(console, RIGHT_READ | RIGHT_WRITE | RIGHT_TRANSFER)?;
    // **逐字节写，不用 `copy_from_slice`/`to_le_bytes`**：两者都会在 `.rodata` 里落常量
    // （前者是长度断言的格式化串，后者是临时数组），用户镜像基址在 4 GiB 之上 ⇒
    // `R_X86_64_32S`（A3 全程撞了四族，统一解法见 ADR-131）。
    let mut hdr = [0u8; SI_HDR];
    put_u32(&mut hdr, 0, u32::from_le_bytes(SI_MAGIC));
    hdr[4] = 0; // ABI major
    hdr[5] = 0;
    hdr[6] = ((crate::abi_info() >> 16) & 0xFF) as u8;
    hdr[7] = 0;
    put_u32(&mut hdr, 8, 1); // nhandles
    // S2（ADR-115）：子进程的 argv[0] = 这条路径。内核 16 号拿它和签名包的覆盖名比；
    // 不写的话子进程拿到 `(0,0)`，闸门永远走"无覆盖"（BACKLOG 390 的前置勘误）。
    const ARGS_OFF: u64 = 280;
    if argv0.is_empty() {
        return Err(RTError::INVALID);
    }
    if argv0.len() + 1 > 512 {
        return Err(RTError::TOOLONG);
    }
    put_u32(&mut hdr, 12, ARGS_OFF as u32);
    put_u32(&mut hdr, 16, (argv0.len() + 1) as u32);
    vmo_write(si, 0, &hdr)?;
    vmo_write(si, ARGS_OFF, argv0)?;
    let nul = [0u8; 1];
    vmo_write(si, ARGS_OFF + argv0.len() as u64, &nul)?;
    let mut desc = [0u8; SI_DESC_BYTES];
    put_u32(&mut desc, 0, ROLE_LOG);
    put_u64(&mut desc, 8, con_dup);
    vmo_write(si, SI_OFF_HANDLES as u64, &desc)?;
    let si_va = stack_top + PAGE;
    let mapped = vmo_map(proc, si, si_va, false, false)?;
    // 15 号（entry/栈顶来自段表）→ 16 号（首参 = SI 页在子 AS 里的 VA）。
    let th = thread_create(proc, l.img.entry, stack_top, 0)?;
    process_start(proc, th, si, mapped)?;
    Ok(proc)
}

/// 等一个进程收工，返回退出码（`None` = 超时）。
pub fn wait_exit(proc: Handle, timeout_ms: u64) -> Result<Option<u32>, RTError> {
    match process_wait(proc, timeout_ms)? {
        Some(o) => Ok(Some(o.exit_code)),
        None => Ok(None),
    }
}

/// 一步到位：装 + 起 + 等。返回退出码（`None` = 超时仍未收工）。
///
/// 超时**不杀**目标：调用方拿到 `None` 之后要有自己的判断（shell 的做法是提示
/// "还在跑"，而不是替使用者开枪——18 号杀进程是个独立决定）。
pub fn run(path: &[u8], console: Handle, job: Handle, timeout_ms: u64) -> Result<Option<u32>, RTError> {
    let l = load(path)?;
    let proc = launch(&l, console, job, path)?;
    wait_exit(proc, timeout_ms)
}
