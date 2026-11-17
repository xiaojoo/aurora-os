//! A2/A3 切片（ADR-130 / ADR-131 草案）：**A2 语义的被启动方 + A3 用户态装载器**。
//!
//! 两种行为，由 argv[0] 决定：
//! - 不以 `.ELF` 结尾（a2-exec 档给 "execprobe"）：打印 `argv[0]` 后 `exit(7)`——
//!   证明 argv 区与继承 stdout 打通（ADR-130 判定行）；
//! - 以 `.ELF` 结尾（a3-exec 档给 "HELLO.ELF"）：**自己把卷上的目标 ELF 装载并运行**——
//!   22 号 open → 顺序读块（无 24 号 seek，产品档没有它）→ 按段过滤写进段 VMO →
//!   14 号映射 → 建栈页 → 构造 SI 页（ROLE_LOG + 自己控制台的 dup）→ 11/15/16/17。
//!
//! 判据锚（a3-exec 档）：串口出现
//! `execprobe: run:HELLO.ELF open=0x… read=0x… entry=0x100000000 spawn=0x0 wait=timeout`
//! ——open/read 证明卷路径，entry 证明用户态段表解析，spawn=0 证明 16 号放行，
//! wait=timeout 是 hello 的已知行为（它写完数据段就自旋，不 exit）。
//!
//! 全部 syscall 走 `aurora-user-runtime`；本文件 unsafe 只剩对 runtime 的
//! `handle_of_role` / `args_at` 两个 unsafe fn 的调用，以及 MSGS 的 lea/切片（同 shell 形状）。

#![no_std]
#![no_main]

use aurora_user_runtime as rt;

// 提示串：**static blob + RIP 相对 lea**（字面量取址在 4 GiB 之上会退化成
// R_X86_64_32S，链接期 out of range——shell MSGS 同一条纪律）。
// 布局（偏移/长度）由 tools 侧对账：0|19 argv 前缀 · 19|1 换行 · 20|13 run 头 ·
// 33|6 " open=" · 39|6 " read=" · 45|7 " entry=" · 52|7 " spawn=" · 59|6 " wait=" ·
// 65|8 "timeout\n" · 73|4 "err=" · 77|16 十六进制字表。
static MSGS: [u8; 104] =
    *b"execprobe: argv[0]=\nrun:HELLO.ELF open= read= entry= spawn= wait=timeout\nerr=0123456789abcdef0xexit:.ELF";

const M_ARGV: (usize, usize) = (0, 19);
const M_NL: (usize, usize) = (19, 1);
const M_RUN: (usize, usize) = (20, 13);
const M_OPEN: (usize, usize) = (33, 6);
const M_READ: (usize, usize) = (39, 6);
const M_ENTRY: (usize, usize) = (45, 7);
const M_SPAWN: (usize, usize) = (52, 7);
const M_WAIT: (usize, usize) = (59, 6);
const M_TIMEOUT: (usize, usize) = (65, 8);
const M_ERR: (usize, usize) = (73, 4);
const M_HEX: (usize, usize) = (77, 16);
// 字面量（b"0x" / b"exit" / b".ELF"）也必须是 blob 的一段：字面量的取址是 anon rodata
// 常量，通过 32S 引用（2026-11-17 实测同族）。
const M_ZEROX: (usize, usize) = (93, 2);
const M_EXIT: (usize, usize) = (95, 5);
const M_ELF: (usize, usize) = (100, 4);

// **块缓冲必须放 .bss，不能放栈**：execprobe 的内核栈只有一页（4 KiB），
// run_image 里一个 [u8; 4096] 局部数组就会把栈顶穿出去——实测 #PF
// `rip=0x100000151 cr2=0x100100f80 err=0x6`（用户态写、保护违规）。
// 取址用 asm lea（RIP 相对）：static 数组的地址若被编译器降成绝对立即数，
// 4 GiB+ 链接基址下就是 R_X86_64_32S（同族坑见 MSGS）。
static mut CHUNK: [u8; 4096] = [0u8; 4096];

#[inline(never)]
fn chunk_base() -> *mut u8 {
    let p: *mut u8;
    // SAFETY: lea 只取地址；CHUNK 是 'static 的 .bss 数组，唯一借出方是本程序单线程。
    unsafe {
        core::arch::asm!(
            "lea {}, [rip + {sym}]",
            out(reg) p,
            sym = sym CHUNK,
            options(nomem, nostack, preserves_flags)
        );
    }
    p
}

#[inline(never)]
fn msgs_base() -> u64 {
    let base: u64;
    // SAFETY: lea 只取地址不访存；RIP 相对寻址与基址无关。
    unsafe {
        core::arch::asm!(
            "lea {}, [rip + {sym}]",
            out(reg) base,
            sym = sym MSGS,
            options(nomem, nostack, preserves_flags)
        );
    }
    base
}

fn msg(m: (usize, usize)) -> &'static [u8] {
    // SAFETY: 偏移/长度来自本文件常量，恒在 MSGS 界内。
    unsafe { core::slice::from_raw_parts((msgs_base() + m.0 as u64) as *const u8, m.1) }
}

/// 以 0x 前缀的十六进制打印（判据锚的可读值）。无堆：按半字节取字表。
fn put_hex(out: rt::Handle, v: u64) {
    let table = msg(M_HEX);
    let _ = rt::console_write(out, msg(M_ZEROX));
    let mut started = false;
    for shift in (0..16).rev() {
        let nib = ((v >> (shift * 4)) & 0xf) as usize;
        if nib != 0 {
            started = true;
        }
        if started || shift == 0 {
            // SAFETY: nib < 16，table 恒为 16 字节字表。
            let b = [unsafe { *table.get_unchecked(nib) }];
            let _ = rt::console_write(out, &b);
        }
    }
}

/// 失败出口：串口打**真实错误码**（hex），退出码 = 200 + 站点号（内核收工行可读）。
fn fail(out: rt::Handle, at: (usize, usize), code: i64, site: u8) -> ! {
    let _ = rt::console_write(out, msg(at));
    put_hex(out, code as u64);
    let _ = rt::console_write(out, msg(M_NL));
    rt::exit(200 + site as u64)
}

/// A3：装载并运行卷上的 `name`（8.3 名，ASCII）。不返回。
fn run_image(name: &[u8], out: rt::Handle, si_va: u64) -> ! {
    // 22 号：open（fs_open 自 mount 固定卷，不依赖挂载表）。路径按字节给，非 UTF-8 也照传。
    let fh = match rt::file_open(name, 0) {
        Ok(h) => h,
        Err(e) => fail(out, M_ERR, e.0, 1),
    };
    // 头块：e_ehdr 64 + phdr ≤ 8×56；4 KiB 足够。缓冲在 .bss（见 CHUNK 的注释）。
    // SAFETY: 单线程，本函数独占 CHUNK；长度按 4096 常量。
    let chunk = unsafe { core::slice::from_raw_parts_mut(chunk_base(), 4096) };
    let hn = match rt::file_read(fh, chunk) {
        Ok(n) => n,
        Err(e) => fail(out, M_ERR, e.0, 2),
    };
    // 25 号 stat：整文件大小（parse 的段界校验要用它，头块只是文件的一段）。
    let st = match rt::file_stat(fh) {
        Ok(s) => s,
        Err(e) => fail(out, M_ERR, e.0, 7),
    };
    let head = match chunk.get(..hn) {
        Some(v) => v,
        None => fail(out, M_ERR, -5, 95),
    };
    let img = match rt::elf::parse(head, st.size() as u64) {
        Ok(i) => i,
        Err(e) => fail(out, M_ERR, e.0, 3),
    };
    // 段 VMO 先建，头块内容先按段过滤写一遍，再顺序读剩余块。
    let (sv, _nseg) = match rt::elf::create_seg_vmos(&img) {
        Ok(v) => v,
        Err(e) => fail(out, M_ERR, e.0, 4),
    };
    if let Err(e) = rt::elf::write_chunk(&img, &sv, head, 0) {
        fail(out, M_ERR, e.0, 5);
    }
    let mut off_cur = hn as u64;
    let mut total = hn as u64;
    loop {
        let n = match rt::file_read(fh, chunk) {
            Ok(n) => n,
            Err(e) => fail(out, M_ERR, e.0, 6),
        };
        if n == 0 {
            break;
        }
        let part = match chunk.get(..n) {
            Some(v) => v,
            None => fail(out, M_ERR, -4, 96),
        };
        if let Err(e) = rt::elf::write_chunk(&img, &sv, part, off_cur) {
            fail(out, M_ERR, e.0, 7);
        }
        off_cur += n as u64;
        total += n as u64;
    }
    let _ = rt::handle_close(fh);

    // **让被装载的程序自己退出**：hello 的 `link.ld` 把 `.slots` 摆在数据段最前
    // （VA 0x100002000），第 48 字节是 `OFF_FLAG`；写 `FLAG_EXIT = 1` 它就跑完
    // 自检后打 3 号退出。这样 17 号拿到的是**真实退出码**，而不是"目标自旋 ⇒ 超时"
    // 那种弱观测（弱观测分不清"跑起来了但没退"与"根本没跑"）。
    // 找**可写段**（不硬编码段号）：hello 的 .slots 在 data 段首，与 link.ld 的
    // "`.slots` 放在 data 段的最前面"是同一条约定。
    {
        let mut flag = [0u8; 8];
        flag[0] = 1; // FLAG_EXIT
        let mut done = false;
        for i in 0..img.nseg {
            let s = match img.segs.get(i) {
                Some(v) => *v,
                None => fail(out, M_ERR, -9, 18),
            };
            if s.w == 0 {
                continue;
            }
            if let Err(e) = rt::vmo_write(sv[i], 48, &flag) {
                fail(out, M_ERR, e.0, 18);
            }
            done = true;
            break;
        }
        if !done {
            fail(out, M_ERR, -9, 18); // 没有可写段 ⇒ 不是我们认识的容器形状
        }
    }

    // 判据第一、二格：open 成功（fh 值）+ 读到全文件（hello 17288 字节）。
    let _ = rt::console_write(out, msg(M_RUN));
    let _ = rt::console_write(out, msg(M_OPEN));
    put_hex(out, fh);
    let _ = rt::console_write(out, msg(M_READ));
    put_hex(out, total);
    let _ = rt::console_write(out, msg(M_ENTRY));
    put_hex(out, img.entry);

    // 11 号：进程对象。ROLE_JOB 来自 A2 语义（stage 给的 hj 带 CREATE|TRANSFER）。
    // SAFETY: si_va 契约同 find_console（内核校验过、只读、存活期不解映射）。
    let job = match unsafe { rt::handle_of_role(si_va, rt::ROLE_JOB) } {
        Some(h) => h,
        None => fail(out, M_ERR, -8, 92),
    };
    let proc = match rt::process_create(job) {
        Ok(h) => h,
        Err(e) => fail(out, M_ERR, e.0, 8),
    };
    // 14 号：逐段映射进子 AS（VA 对账在 elf::map_segs 里）。
    if let Err(e) = rt::elf::map_segs(proc, &img, &sv) {
        fail(out, M_ERR, e.0, 9);
    }
    // 栈：一页，放在最大段末尾页对齐之后 4 页（窗口内、避开所有段）。
    let stack_va = (img.stack_top - rt::elf::PAGE) + 4 * rt::elf::PAGE;
    let stack_top = stack_va + rt::elf::PAGE;
    let stack_vmo = match rt::vmo_create(1) {
        Ok(h) => h,
        Err(e) => fail(out, M_ERR, e.0, 10),
    };
    if let Err(e) = rt::vmo_map(proc, stack_vmo, stack_va, true, false) {
        fail(out, M_ERR, e.0, 11);
    }
    // SI 页给子进程：头 24 字节 + 一条 ROLE_LOG 描述（hello 的 find_console 认它）。
    // 控制台用 dup 的副本转移——transfer 会把自己这份移走，剩我们自己的不动。
    let con_dup = match rt::handle_dup(out, rt::RIGHT_READ | rt::RIGHT_WRITE | rt::RIGHT_TRANSFER) {
        Ok(h) => h,
        Err(e) => fail(out, M_ERR, e.0, 12),
    };
    let si = match rt::vmo_create(1) {
        Ok(h) => h,
        Err(e) => fail(out, M_ERR, e.0, 13),
    };
    // **逐字节写**，不用 to_le_bytes 的临时数组：它的取址会被提升成 `.rodata..Lanon`
    // 常量模板，4 GiB+ 链接基址下 R_X86_64_32S 溢出（同日第三次：to_le_bytes/bool 数组
    // 零值/查表——用户程序里"编译器生成的只读模板"全会炸）。
    let mut hdr = [0u8; 24];
    // SI_MAGIC = 0x4155_524F（LE：4F 52 55 41）
    hdr[0] = 0x4F;
    hdr[1] = 0x52;
    hdr[2] = 0x55;
    hdr[3] = 0x41;
    hdr[4] = 0; // ABI major = 0
    hdr[5] = 0;
    // ABI minor 取**运行期**的值：写死 12 在 ABI 0.13/0.14 的构建里会被 16 号校验拒成 -1
    // （qoder 合并时实测）。高位是 major、16..32 是 minor，与内核 `abi_word()` 同一形状。
    hdr[6] = ((rt::abi_info() >> 16) & 0xFF) as u8;
    hdr[7] = 0;
    hdr[8] = 1; // nhandles = 1
    hdr[9] = 0;
    hdr[10] = 0;
    hdr[11] = 0;
    if rt::vmo_write(si, 0, &hdr).is_err() {
        fail(out, M_ERR, -7, 93);
    }
    let mut desc = [0u8; 16];
    desc[0] = rt::ROLE_LOG as u8; // 5
    for i in 0..8 {
        desc[8 + i] = (con_dup >> (i * 8)) as u8;
    }
    if rt::vmo_write(si, 24, &desc).is_err() {
        fail(out, M_ERR, -6, 94);
    }
    // si_va 给子进程：放在栈页之上（窗口内空位）。
    let si_va2 = stack_top + rt::elf::PAGE;
    let mapped = match rt::vmo_map(proc, si, si_va2, false, false) {
        Ok(v) => v,
        Err(e) => fail(out, M_ERR, e.0, 14),
    };
    // 15 号：线程（entry/栈顶来自段表解析）。第四参 arg=0，16 号会把 si_va 填进去。
    let th = match rt::thread_create(proc, img.entry, stack_top, 0) {
        Ok(h) => h,
        Err(e) => fail(out, M_ERR, e.0, 15),
    };
    // 16 号：启动。spawn=0 是判据第三格。
    let sr = match rt::process_start(proc, th, si, mapped) {
        Ok(()) => 0u64,
        Err(e) => fail(out, M_ERR, e.0, 16),
    };
    let _ = rt::console_write(out, msg(M_SPAWN));
    put_hex(out, sr);
    // 17 号：等 3 秒。hello 写完数据段就自旋，不 exit ⇒ 超时是**预期**（判据第四格）。
    let w = rt::process_wait(proc, 3000);
    let _ = rt::console_write(out, msg(M_WAIT));
    match w {
        Ok(Some(o)) => {
            // `wait=exit:0x<码>`——第三、四格锚点：子进程真跑了、真退了、码对得上。
            let _ = rt::console_write(out, msg(M_EXIT));
            put_hex(out, o.exit_code as u64);
            let _ = rt::console_write(out, msg(M_NL));
        }
        Ok(None) => {
            let _ = rt::console_write(out, msg(M_TIMEOUT));
        }
        Err(e) => fail(out, M_ERR, e.0, 17),
    }
    rt::exit(0)
}

/// argv 区约定：首串是 argv[0]（NUL 结尾），从 args_off 起到 args_len。
fn first_arg(args: &[u8]) -> &[u8] {
    match args.iter().position(|&b| b == 0) {
        Some(i) => &args[..i],
        None => args,
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态 panic 就停在这一核上自旋（与 fileprobe/shell 同一形状）。
    // SAFETY: 用户态自旋；内核的看门狗/时间片会记下这台核不动。
    loop {
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // A2 的核心验证点：stdout 来自**继承**（ROLE_STDOUT），不是 ROLE_LOG。
    // SAFETY: si_va 由内核校验并映射（user+只读），契约同 rt::find_console。
    let stdout = match unsafe { rt::handle_of_role(si_va, rt::ROLE_STDOUT) } {
        Some(h) => h,
        None => rt::exit(11),
    };
    // SAFETY: 同上；args 区已被内核校验在页内且不与句柄表重叠（ADR-130 决策 2）。
    let args = match unsafe { rt::args_at(si_va) } {
        Some(a) if !a.is_empty() => a,
        _ => rt::exit(22),
    };
    let name = first_arg(args);
    let _ = rt::console_write(stdout, msg(M_ARGV));
    let _ = rt::console_write(stdout, name);
    let _ = rt::console_write(stdout, msg(M_NL));
    // A3：目标是 ELF 文件 ⇒ 装载并运行；否则 A2 行为（打印后 exit(7)）。
    let tail = name.len().checked_sub(4).and_then(|i| name.get(i..));
    if tail == Some(msg(M_ELF)) {
        run_image(name, stdout, si_va);
    }
    rt::exit(7);
}