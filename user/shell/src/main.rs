//! S5c：第一个**交互式**用户程序——串口 shell。
//!
//! 与 hello/probe 的三条约定相同（ADR-025 / §10.2 / elf.rs）：
//! 1. 入口走 `int 0x80`，所以**不**声明 `rcx`/`r11` 被破坏（那是 SYSCALL 的硬件行为）。
//! 2. 号在 `rax`，参数 `rdi/rsi/rdx`，返回 `rax`，负数是 `-ErrorCode`。
//! 3. 段地址与对齐由 `link.ld` 保证，不靠"我记得链接脚本怎么排的"。
//!
//! **控制台句柄从哪来**：`process_start` 的第④步 `set_thread_arg(gidx, si_va)`
//! 把 StartupInfo 那一页在**子 AS 里的 VA** 作为首参交进来（`user.rs` 的注释明写
//! "首参 = 那一页在子 AS 里的 VA"）。所以 `_start` 的第一个参数就是它。
//! 内核按 `role == ROLE_LOG(5)` 把控制台句柄转移给我们（`main.rs` 的 S5b 段），
//! 我们**只认角色号**，不认"第几条"——顺序不是契约，角色才是。
//!
//! **命令只用真实存在的 syscall**：help/echo/ping/abi/exit。
//! `ps`/`mem`/`reboot` 需要新号，本片**不做**，也不假装做了。
//!
//! A3：命令分发重构为"解析器 + 注册表"——`parser.rs` 负责切词，
//! `registry.rs` 持有全部命令与 unknown 输出；本文件只剩读行循环。
//! A2 接线：串口底座（int 0x80 入口 / con_read/con_write / SI 页解析）迁到
//! `aurora-user-runtime`，本 crate 不再持有任何 syscall 底座 unsafe。
//! 五个命令与 unknown 提示的串口输出保持**逐字节不变**（回归安全线）。

#![no_std]
#![no_main]

use aurora_user_runtime as rt;

mod parser;
mod registry;

// A2 接线：调用号（SYS_*）与 StartupInfo 布局（SI_*）随 syscall 底座一起迁到
// `aurora-user-runtime`——本文件不再直接打 int 0x80，也不再解析 SI 页。
// shell 侧保留的 unsafe 只剩：panic/收尾的自跳转与对 `rt::find_console`（unsafe fn）
// 的那一处调用，见 unsafe-census.md 的 user/shell 节。

/// 所有提示串拼成一个静态 blob。**为什么不用字符串字面量**：镜像基址在 4 GiB 之上，
/// `relocation-model=static` 下字面量地址会退化成 `R_X86_64_32S` 绝对重定位，链接期 out of range
/// （hello/probe 的模块头都记过这个坑，本轮实测又撞一次）。改成 RIP 相对 lea 取基址 + 常量偏移。
/// S6u：横幅的前导 `\x0a` 去掉了——那是当年为了跟上面的内核日志隔开留的，
/// ADR-096 之后画面正文只有会话输出，前面什么都没有，那一格就成了纯粹的空行。
static MSGS: [u8; 1356] = *b"dmesg: usage\x0admesg: err=\x0admesg: tail\x0acommands: help | echo <text> | ping | abi | ps | free | top | kill | exit\x0aAurora OS 6.1.0-aurora (tty1)\x0aaurora@os:~$ \x0aline too long, discarded\x0aunknown command:  (try help)\x0aping=abi_info=bye\x0a\x08 \x08^C\x0arun:  exit= (timeout) error=usage: run <path>\x0a-PID GEN THR ST PAGES\x0aps: no job handle\x0alivedead ps: error=free: procs= threads= pages=#\x0atop: usage\x0aframe kill: usage\x0akilled=dmesg: usage\x0admesg: err=dmesg: tail\x0alspci: usage\x0auptime: sleep <ms>\x0aping <ip>\x0afrom \x20\x0ap\x2e\x0a: seq=\x0atimeout\x0aip: usage\x0alink addr mtu=state=up\x0adown\x0amac gw dns \x3als: cat: d f  entries bytes= fnv=pwd: cd:  not a directoryusage: cd <path>usage: cat <path> | cd | pwdneigh neigh: empty\x0aip: usage\x0a\x0aroute default via  mask=/lsdev usage\x0aclass 0x count=devctl status\x0adevctl usage\x0apciblknetdisplaybridgeotheruid= gid= caps=whoami: id: usage: whoami\x0ano creddenied: part: entries= used= usable= lba=type=0xpart: no disk\x0aclear: no fb\x0aclear: done\x0apipe: empty segment\x0apipe: input truncated\x0agrep: usage <pattern>\x0agrep: no input\x0awc: usage\x0a lines= words= bytes=\x0astat: usage <path>\x0astat: kind= size= fnv=head: usage [-n N] <path>\x0atail: usage [-n N] <path>\x0afile: usage <path>\x0afile: ELF\x0afile: empty\x0afile: text\x0afile: binary\x0ausage: uname\x0aaurora usage: arch\x0ax86_64 usage: meminfo\x0a total= free= used= page=nslookup: usage <name>\x0anslookup: name= ip= ancount= rcode=nslookup: no answer\x0a";

const M_HELP: (usize, usize) = (37, 14);
const M_BANNER: (usize, usize) = (111, 30);
const M_PROMPT: (usize, usize) = (141, 13);
const M_NL: (usize, usize) = (110, 1);
const M_TOOLONG: (usize, usize) = (155, 25);
const M_UNKNOWN: (usize, usize) = (180, 17);
const M_TRYHELP: (usize, usize) = (197, 12);
const M_PING: (usize, usize) = (209, 5);
const M_ABI: (usize, usize) = (214, 9);
const M_BYE: (usize, usize) = (223, 4);
const M_BS: (usize, usize) = (227, 3);
const M_INT: (usize, usize) = (230, 3);
const M_RUN_PREFIX: (usize, usize) = (233, 5);
const M_RUN_EXIT: (usize, usize) = (238, 6);
const M_RUN_TIMEOUT: (usize, usize) = (244, 10);
const M_RUN_ERR: (usize, usize) = (254, 7);
const M_RUN_USAGE: (usize, usize) = (261, 18);
const M_MINUS: (usize, usize) = (279, 1);
const M_PS_HDR: (usize, usize) = (280, 21);
const M_PS_NOJOB: (usize, usize) = (301, 18);
const M_LIVE: (usize, usize) = (319, 4);
const M_DEAD: (usize, usize) = (323, 4);
const M_SP: (usize, usize) = (327, 1);
const M_PS_ERR: (usize, usize) = (328, 10);
const M_FREE_PFX: (usize, usize) = (338, 12);
const M_FREE_THR: (usize, usize) = (350, 9);
const M_FREE_PAGES: (usize, usize) = (359, 7);
// `top`（ADR-133）：表头与 ps 同列名，另加"快照序号"前缀行与 usage。
const M_TOP_USAGE: (usize, usize) = (368, 11);
const M_TOP_FRAME: (usize, usize) = (379, 6);
// `kill`（ADR-134）：usage 与成功后的收掉线程数。
const M_KILL_USAGE: (usize, usize) = (385, 12);
const M_KILLED: (usize, usize) = (397, 7);
// `lspci`（ADR-136）：usage。
const M_LSPCI_USAGE: (usize, usize) = (440, 13);
// `uptime`（ADR-137）：参数被拒时的提示；成功路径打数字（put_u64）+ 换行。
const M_UPTIME_USAGE: (usize, usize) = (453, 8);
// `sleep`（ADR-137 续）：usage。
const M_SLEEP_USAGE: (usize, usize) = (461, 11);
// `ping`（ADR-143）：usage。
const M_PING_USAGE: (usize, usize) = (472, 10);
// `ping` 的输出件：来自/点/序号/超时。
const M_PING_FROM: (usize, usize) = (482, 5);
const M_PING_DOT: (usize, usize) = (490, 1);  // "." 单字节（带\n 的那个是坑位）
const M_PING_SEQ: (usize, usize) = (492, 6);
const M_PING_TIMEOUT: (usize, usize) = (499, 7);
// `ip link` / `ip addr`（ADR-144）：子命令与显示件。
const M_IP_USAGE: (usize, usize) = (507, 10);
const M_IP_LINK: (usize, usize) = (517, 5);
const M_IP_ADDR: (usize, usize) = (522, 5);
const M_IP_MTU: (usize, usize) = (527, 4);
const M_IP_STATE: (usize, usize) = (531, 6);
const M_IP_UP: (usize, usize) = (537, 3);
const M_IP_DOWN: (usize, usize) = (540, 5);
const M_IP_MAC: (usize, usize) = (545, 4);
const M_IP_GW: (usize, usize) = (549, 3);
const M_IP_DNS: (usize, usize) = (552, 4);
const M_COLON: (usize, usize) = (556, 1);
// `ip neigh`（ADR-145）：子命令 + 空表提示。
const M_NEIGH: (usize, usize) = (659, 6);
const M_NEIGH_EMPTY: (usize, usize) = (665, 13);
// `ip route`（ADR-147）：一行默认路由。
const M_ROUTE_NL: (usize, usize) = (688, 1);
// ADR-148：掩码前缀显示件（" mask=/"）。
const M_ROUTE_MASK_EQ: (usize, usize) = (707, 6);
const M_ROUTE_SLASH: (usize, usize) = (713, 1);
const M_ROUTE_DEFAULT: (usize, usize) = (689, 18);
const M_IP_USAGE2: (usize, usize) = (678, 10);
// `dmesg`（ADR-135）：usage 与读取失败前缀。
const M_LS: (usize, usize) = (557, 4);
const M_CAT: (usize, usize) = (561, 5);
const M_D: (usize, usize) = (566, 2);
const M_F: (usize, usize) = (568, 2);
const M_ENTRIES: (usize, usize) = (570, 8);
const M_BYTES: (usize, usize) = (578, 7);
const M_FNV: (usize, usize) = (585, 5);
const M_PWD: (usize, usize) = (590, 5);
const M_CD: (usize, usize) = (595, 4);
const M_NOTDIR: (usize, usize) = (599, 16);
const M_CD_USAGE: (usize, usize) = (615, 16);
const M_CAT_USAGE: (usize, usize) = (631, 17);
const M_HELP2: (usize, usize) = (648, 11);
const M_DMESG_USAGE: (usize, usize) = (0, 13);
// lsdev / devctl（ADR-149）：设备类只读视图。
const M_LSDEV_USAGE: (usize, usize) = (714, 12);
// whoami / id（ADR-150）：凭据显示件。
const M_CRED_UID: (usize, usize) = (795, 4);
const M_CRED_GID: (usize, usize) = (799, 5);
const M_CRED_CAPS: (usize, usize) = (804, 6);
const M_WHOAMI_PFX: (usize, usize) = (810, 8);
const M_ID_PFX: (usize, usize) = (818, 4);
const M_WHOAMI_USAGE: (usize, usize) = (822, 14);
const M_CRED_NONE: (usize, usize) = (836, 7);
// 授权拒绝（ADR-151）。
const M_DENIED: (usize, usize) = (843, 8);
// `part`（ADR-152）：分区只读查询。
const M_PART_ENTRIES: (usize, usize) = (851, 14);
const M_PART_USED: (usize, usize) = (865, 6);
const M_PART_USABLE: (usize, usize) = (871, 8);
const M_PART_LBA: (usize, usize) = (879, 5);
const M_PART_TYPE: (usize, usize) = (884, 7);
const M_PART_NODISK: (usize, usize) = (891, 14);
// `clear`（ADR-153，D3）：清屏。
const M_CLEAR_NOFB: (usize, usize) = (905, 13);
const M_CLEAR_DONE: (usize, usize) = (918, 12);
// 管道（ADR-155）。
const M_PIPE_EMPTY: (usize, usize) = (930, 20);
const M_PIPE_TRUNC: (usize, usize) = (950, 22);
// grep / wc（ADR-155：管道的两个真实消费者）。
const M_GREP_USAGE: (usize, usize) = (972, 22);
const M_GREP_NOIN: (usize, usize) = (994, 15);
const M_WC_USAGE: (usize, usize) = (1009, 10);
const M_WC_LINES: (usize, usize) = (1019, 7);
const M_WC_WORDS: (usize, usize) = (1026, 7);
const M_WC_BYTES: (usize, usize) = (1033, 7);
// stat / head / tail / file（ADR-156：§10.2 的四个只读命令）。
const M_STAT_USAGE: (usize, usize) = (1041, 19);
const M_STAT_KIND: (usize, usize) = (1060, 11);
const M_STAT_SIZE: (usize, usize) = (1071, 6);
const M_STAT_FNV: (usize, usize) = (1077, 5);
const M_HEAD_USAGE: (usize, usize) = (1082, 26);
const M_TAIL_USAGE: (usize, usize) = (1108, 26);
const M_FILE_USAGE: (usize, usize) = (1134, 19);
const M_FILE_ELF: (usize, usize) = (1153, 10);
const M_FILE_EMPTY: (usize, usize) = (1163, 12);
const M_FILE_TEXT: (usize, usize) = (1175, 11);
const M_FILE_BIN: (usize, usize) = (1186, 13);
// uname / arch / meminfo（ADR-157，§10.3 的三条）。
const M_UNAME_USAGE: (usize, usize) = (1199, 13);
const M_UNAME_OUT: (usize, usize) = (1212, 6);
const M_ARCH_USAGE: (usize, usize) = (1218, 13);
const M_ARCH_OUT: (usize, usize) = (1231, 6);
const M_MEM_USAGE: (usize, usize) = (1237, 16);
const M_MEM_TOTAL: (usize, usize) = (1253, 7);
const M_MEM_FREE: (usize, usize) = (1260, 6);
const M_MEM_USED: (usize, usize) = (1266, 6);
const M_MEM_PAGE: (usize, usize) = (1272, 6);
// nslookup（ADR-158，§10.4 的第三条）。
const M_NS_USAGE: (usize, usize) = (1278, 23);
const M_NS_NAME: (usize, usize) = (1301, 15);
const M_NS_IP: (usize, usize) = (1316, 4);
const M_NS_AN: (usize, usize) = (1320, 9);
const M_NS_RC: (usize, usize) = (1329, 7);
const M_NS_NOANS: (usize, usize) = (1336, 20);
const M_CLASS_PREFIX: (usize, usize) = (726, 8);
const M_COUNT: (usize, usize) = (734, 7);
const M_DEVCTL_STATUS: (usize, usize) = (741, 13);
const M_DEVCTL_USAGE: (usize, usize) = (755, 13);
const M_CLASS_PCI: (usize, usize) = (768, 3);
const M_CLASS_BLK: (usize, usize) = (771, 3);
const M_CLASS_NET: (usize, usize) = (774, 3);
const M_CLASS_DISPLAY: (usize, usize) = (777, 7);
const M_CLASS_BRIDGE: (usize, usize) = (784, 6);
const M_CLASS_OTHER: (usize, usize) = (790, 5);
const M_DMESG_ERR: (usize, usize) = (13, 11);
const M_DMESG_HDR: (usize, usize) = (25, 12);
/// blob 的真实基址（RIP 相对 lea，不产生 32 位绝对重定位）。
fn msgs_base() -> u64 {
    let b: u64;
    // SAFETY: lea 只算地址不访存、不动栈；RIP 相对 => 无绝对重定位。
    unsafe {
        core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym MSGS,
                         options(nomem, nostack, preserves_flags));
    }
    b
}

/// 按 (偏移,长度) 取一条消息。
fn msg(m: (usize, usize)) -> &'static [u8] {
    // SAFETY: 基址来自 msgs_base()（本程序 .rodata 里的 MSGS），m 是上面那组常量，
    // 偏移+长度都落在 blob 内；只读、生命周期是整个程序。
    unsafe { core::slice::from_raw_parts((msgs_base() + m.0 as u64) as *const u8, m.1) }
}

/// 一行命令的上限。超了就丢弃整行并提示——不静默截断成另一条命令。
const LINE_MAX: usize = 128;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // 用户态没有停机权，也不能用 hlt/cli（ring3 下都是 #GP，hello 的注释里记过实测）。
    loop {
        unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) };
    }
}

/// 去掉首尾的空格/Tab（脚本模式下 `;` 两侧常带空格）。
fn trim_ascii(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
        if c == b' ' || c == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = b.split_last() {
        if c == b' ' || c == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// 往控制台写一段字节。
/// A2 接线：本体迁到 `rt::console_write`。旧版返回 syscall rax，但**全仓没有调用方
/// 读它**（逐处核对过）——签名顺势改 `()`，错误也和旧版一样不上抛（旧版忽略 rax，
/// 交互程序对写失败没有可恢复动作；`let _` 是显式声明"与旧版同口径地忽略"，不是吞错）。
fn con_write(h: u64, s: &[u8]) {
    // ADR-155：管道左段的输出先落进 sink 缓冲，右段再从缓冲读。
    // **在这里拦一层**而不是改 216 个调用点：`con_write` 是唯一输出入口，
    // 一处拦截就让全部命令自动支持管道。
    if let Some(n) = sink_write(s) {
        let _ = n;
        return;
    }
    let _ = rt::console_write(h, s);
}

/// 执行一段命令行（可能是管道）。返回 false = 收到退出请求。
///
/// **交互模式与脚本模式（argv）共用这一个函数**：之前两条路径各写一份，
/// 管道只在交互路径里生效，argv 档静默把 `|` 当成参数（实测 `ls | grep NOTES`
/// 打 `ls: /|`）。共用一份就不会再分叉。
fn run_segments(console: u64, si_va: u64, raw: &[u8], st: &mut ShellState) -> bool {
    let (segs, nseg) = parser::split_pipe(raw);
    if nseg <= 1 {
        let parsed = parser::parse(raw);
        return registry::dispatch(console, si_va, &parsed, st);
    }
    let mut carry: &[u8] = &[];
    let mut trunc = false;
    let mut i = 0usize;
    let mut quit = false;
    while i < nseg {
        let last = i + 1 == nseg;
        let seg = segs.get(i).copied().unwrap_or(&[]);
        let parsed = parser::parse(seg);
        if parsed.cmd.is_empty() {
            con_write(console, msg(M_PIPE_EMPTY));
            break;
        }
        registry::set_stdin(if i == 0 { &[] } else { carry });
        if last {
            if !registry::dispatch(console, si_va, &parsed, st) {
                quit = true;
            }
        } else {
            sink_begin();
            let _ = registry::dispatch(console, si_va, &parsed, st);
            let (buf, tr) = sink_take();
            carry = buf;
            trunc = trunc || tr;
        }
        i += 1;
    }
    registry::set_stdin(&[]);
    if trunc {
        con_write(console, msg(M_PIPE_TRUNC));
    }
    !quit
}

// ---------------------------------------------------------------- ADR-155 管道
//
// 设计：管道左段执行时把 `con_write` 的输出收进一个**定长内存缓冲**，
// 右段执行时从该缓冲取输入。**不建真管道对象、不开并发**——shell 是单线程，
// 两段顺序执行，所以"缓冲"就够。
//
// 容量 4 KiB：一条 `cat /NOTES` 的输出上限（NOTES 是 27 字节，但 `ls`/`dmesg`
// 会长）。超了**截断并记标志**，右段会看到"输入被截断"——不静默丢。

/// sink 缓冲容量。
const SINK_CAP: usize = 4096;

static mut SINK: [u8; SINK_CAP] = [0; SINK_CAP];
static mut SINK_LEN: usize = 0;
static mut SINK_ON: bool = false;
static mut SINK_TRUNC: bool = false;

/// 取 `SINK` 基址。**必须 RIP 相对 `lea`**：
///
/// `&SINK[..]` / `SINK.get_mut(i)` 这类写法会让编译器生成对 `shell::SINK`
/// 的**绝对地址**引用（`R_X86_64_32S`），而镜像基址在 4 GiB 之上 ⇒ 链接期
/// out of range（实测：`cat_each`/`dir_list` 的闭包实例化里各有几处，
/// 报错文本是 `references 'shell::SINK (.llvm.NNN)'`）。
/// 这与 ADR-154 记的 `MSGS` 是同一条纪律。
#[inline]
fn sink_base() -> *mut u8 {
    let p: *mut u8;
    // SAFETY: `lea` 只做地址计算，不读内存；`SINK` 是 'static 定长数组。
    unsafe {
        core::arch::asm!(
            "lea {0}, [rip + {1}]",
            out(reg) p,
            sym SINK,
            options(nostack, preserves_flags)
        );
    }
    p
}

/// 开启 sink（管道左段执行前调用）。
fn sink_begin() {
    // SAFETY: 单线程 shell；这三个静态量只在 `sink_begin`/`sink_write`/`sink_take`
    // 三处读写，都在同一个调用栈里顺序发生，没有并发。
    unsafe {
        SINK_LEN = 0;
        SINK_TRUNC = false;
        SINK_ON = true;
    }
}

/// 关闭 sink 并交出（切片, 是否截断）。
fn sink_take() -> (&'static [u8], bool) {
    // SAFETY: 同 `sink_begin`。返回 'static 切片：SINK 是 'static，且调用方在
    // 下一次 `sink_begin` 之前用完（右段执行期间不会再开 sink）。
    // 用裸指针构造切片，避免 `&SINK[..]` 的绝对地址引用。
    unsafe {
        SINK_ON = false;
        let base = sink_base() as *const u8;
        (core::slice::from_raw_parts(base, SINK_LEN), SINK_TRUNC)
    }
}

/// 若 sink 开着，把 `s` 收进缓冲并返回 `Some(写入字节数)`；否则 `None`。
fn sink_write(s: &[u8]) -> Option<usize> {
    // SAFETY: 同 `sink_begin`。
    unsafe {
        if !SINK_ON {
            return None;
        }
        let base = sink_base();
        let mut n = 0usize;
        while n < s.len() {
            if SINK_LEN >= SINK_CAP {
                SINK_TRUNC = true;
                break;
            }
            if let Some(src) = s.get(n) {
                core::ptr::write(base.add(SINK_LEN), *src);
                SINK_LEN += 1;
                n += 1;
            } else {
                break;
            }
        }
        Some(n)
    }
}

/// 从控制台读**一个**字节。返回 None 表示当前没有输入（21 号不阻塞）。
/// A2 接线：本体迁到 `rt::console_read`；判据与旧版逐字同义（成功且恰好 1 字节）。
fn con_read_byte(h: u64, slot: &mut u8) -> Option<u8> {
    match rt::console_read(h, core::slice::from_mut(slot)) {
        Ok(1) => Some(*slot),
        _ => None,
    }
}

/// Ctrl+C = **行内中断**（S6q）：丢弃已键入的内容、回显 `^C`、重新给提示符。
///
/// 口径写清楚：本内核还没有信号与前台进程组，命令也都是瞬间完成的，所以这里"中断"的是
/// **正在编辑的这一行**，不是某个进程（BACKLOG §261 记着）。
///
/// **为什么单独一个 `#[inline(never)]` 的函数**：把这个字节比较塞进 `_start` 里那串
/// 已有的字节比较（换行/退格/DEL），LLVM 会把整串降成 `switch` + 跳转表，而那张表落在
/// 4 GiB 之上的 `.rodata`——静态链接下取址是绝对重定位，链接器直接报
/// `R_X86_64_32S out of range`（本轮实测两次：加比较、加 xor 都一样）。把它关进一个
/// 只做一次比较的函数里，`_start` 里就只剩一次调用。
#[inline(never)]
fn ctrl_c(console: u64, b: u8) -> bool {
    if b != 0x03 {
        return false;
    }
    con_write(console, msg(M_INT));
    con_write(console, msg(M_PROMPT));
    true
}

/// 把一个小整数按十进制写出去（no_std 里没有格式化器可用，也不引依赖）。
fn put_u64(h: u64, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if v == 0 {
        // 局部数组而不是 `&[b'0']`：后者是 const 提升，会在 .rodata 里落一个字节，
        // 取它的地址就是 32 位绝对重定位（本轮实测：链接器报的那个 .Lanon 段内容正是 b'0'）。
        let zero = [b'0'];
        con_write(h, &zero);
        return;
    }
    while v > 0 {
        i -= 1;
        // 用 get_mut 而不是索引：索引的边界检查在带调试断言的档里会生成 panic Location。
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (v % 10) as u8;
        }
        v /= 10;
    }
    if let Some(tail) = buf.get(i..) {
        con_write(h, tail);
    }
}

// A2 接线：find_console（SI 页解析）整段迁到 `rt::find_console`——两边逐字同源
// （runtime 版注明了出处 main.rs 原实现），Si 页偏移常量也随之迁走。

/// 2026-11-18：shell 自己的**当前目录**（内核只认绝对路径，cwd 纯属 shell 状态）。
/// 初始 `/`；`cd` 校验目标真是目录后整串替换。单线程程序，一个实例在 `_start` 里。
pub struct ShellState {
    pub cwd: [u8; 128],
    pub cwd_len: usize,
}

impl ShellState {
    pub fn new() -> Self {
        let mut cwd = [0u8; 128];
        cwd[0] = b'/';
        ShellState { cwd, cwd_len: 1 }
    }
}
/// 入口。`rdi` = StartupInfo 那一页在子 AS 里的 VA（`process_start` 的 set_thread_arg）。
#[no_mangle]
pub extern "C" fn _start(si_va: u64) -> ! {
    // SAFETY: si_va 由内核校验并映射（user+只读）；`rt::find_console` 的 Safety 契约
    // 与旧 shell 版逐字相同（那一页在读取期间不被解映射）。
    let console = match unsafe { rt::find_console(si_va) } {
        Some(h) => h,
        None => {
            // 没有控制台就什么都做不了。**不**静默自旋假装在跑：
            // 直接 exit(1)，让内核侧的收工读数能看出"shell 没拿到控制台"。
            // `rt::exit` 是 `-> !`：失败时 runtime 侧已带自旋兜底，不再手写第二份 asm。
            rt::exit(1);
        }
    };
    con_write(console, msg(M_BANNER));
    let mut st = ShellState::new();
    // A3（ADR-131）：SI 页的 **argv 区**若带了一条命令，就执行它一次然后退出
    // （`sh -c` 语义）。默认构建的内核不写 argv（0/0），所以交互行为**一字未变**；
    // 有 argv 时不打印提示符——脚本模式不该等输入。
    // SAFETY: si_va 契约同 `find_console`（内核 process_start 校验并映射、user+只读）。
    if let Some(argv) = unsafe { rt::args_at(si_va) } {
        let line = argv.split(|&b| b == 0).next().unwrap_or(&[]);
        // **`;` 分隔多条**：脚本模式（argv）与交互模式的差别只在这里——交互一次一行，
        // 脚本一行可以带几条。空段（`;;`、末尾 `;`）跳过，不产生输出。
        let mut any = false;
        for part in line.split(|&b| b == b';') {
            let cmd = trim_ascii(part);
            if cmd.is_empty() {
                continue;
            }
            any = true;
            con_write(console, cmd);
            con_write(console, msg(M_NL));
            // ADR-155：脚本模式（argv）同样支持管道——与交互模式**共用同一段逻辑**。
            // 之前这里直接 `parse` + `dispatch`，管道在 argv 档里静默失效
            // （实测 `ls | grep NOTES` 把 `|` 当成 `ls` 的参数）。
            run_segments(console, si_va, cmd, &mut st);
        }
        if any {
            rt::exit(0);
        }
    }
    let mut line = [0u8; LINE_MAX];
    let mut len = 0usize;
    let mut overflow = false;
    con_write(console, msg(M_PROMPT));
    loop {
        let mut b = 0u8;
        match con_read_byte(console, &mut b) {
            None => {
                // 没有输入就再问一次。**这是忙等，不是让出**：21 号不阻塞，而 syscall 表里
                // 没有 yield 号（新增号要裁决，本片不做）。占住的核靠时间片抢占轮转，
                // 所以别的任务仍跑得到；阻塞读/唤醒是 BACKLOG §235 记着的欠账。
                continue;
            }
            Some(c) => c,
        };
        if b == b'\n' || b == b'\r' {
            con_write(console, msg(M_NL));
            if overflow {
                con_write(console, msg(M_TOOLONG));
            } else {
                // ADR-155：切管道 → 逐段执行。单段走的就是原来的路径。
                let raw = line.get(..len).unwrap_or(&[]);
                if !run_segments(console, si_va, raw, &mut st) {
                    rt::exit(0);
                }
            }
            len = 0;
            overflow = false;
            con_write(console, msg(M_PROMPT));
            continue;
        }
        if ctrl_c(console, b) {
            len = 0;
            overflow = false;
            continue;
        }
        if b == 0x08 || b == 0x7f {
            if len > 0 {
                len -= 1;
                con_write(console, msg(M_BS));
            }
            continue;
        }
        if len < LINE_MAX {
            if let Some(slot) = line.get_mut(len) {
                *slot = b;
            }
            len += 1;
            // 回显
            let echo = [b];
            con_write(console, &echo);
        } else {
            overflow = true;
        }
    }
}
