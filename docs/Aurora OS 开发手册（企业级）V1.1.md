# Aurora OS 开发手册（企业级）V1.1

**文档编号**：AUR-DEV-1.1　**日期**：2026-11-04　**状态**：草案，待架构评审　**取代**：V1.0《总体架构设计文档》 **适用范围**：第一阶段（x86-64 内核）为强制规范；用户空间、图形、商业发布章节为前瞻性规范。

## 0 阅读指南

### 0.1 相对 V1.0 的修订摘要

| 编号 | 修订 | 原因 | 章节 |
| --- | --- | --- | --- |
| R1 | 增加威胁模型、TCB 与 unsafe 预算 | V1.0 只要求“unsafe 需有理由”，无法审计 | 1.2–1.3 |
| R2 | 增加 IOMMU 与 DMA 隔离 | 设备 DMA 可绕过所有软件隔离 | 8 |
| R3 | 增加启动循环保护、驱动隔离（quarantine）、A/B 回滚 | 崩溃后无法自恢复是 CrowdStrike 事件的核心教训 | 9 |
| R4 | 增加 ACPI、USB、NVMe、virtio、电源管理、混合核心调度 | 真机必需，V1.0 缺失 | 13 |
| R5 | 用户态与 capability 权限模型提前 | 系统调用 ABI 会反向约束内核设计 | 10, 14 |
| R6 | 固化工具链决策（stable、内置目标、集成汇编器） | V1.0 汇编器未定、nightly 依赖不明 | 1.4, 3 |
| R7 | 增加 fuzz、Miri、Kani、loom、真机矩阵 | 仅 QEMU 不足以支撑企业级质量 | 12 |
| R8 | 增加许可证、供应链、生态与差异化定位 | 商业化阻塞项 | 15 |

### 0.2 证据约定

- **\[S#\]**：本次会话中实际检索到的来源，地址见附录 B.1。
- **\[R#\]**：通用权威参考，地址见附录 B.2。**本次会话未逐条核验页面内容**，采用前请自行打开确认。
- **决策**：本手册提出的建议，需评审后固化为 ADR，**不是**来源中的事实。

### 0.3 代码约定

代码是设计骨架，用于固化接口与不变量，**未经完整编译与测试**。第三方 crate（如 limine、x86\_64）的 API 随版本变化，必须固定版本并以该版本文档为准。

## 1 治理、威胁模型与决策

### 1.1 行业教训与本手册对策

| 来源事实 | 本手册对策 |
| --- | --- |
| Linux 维护者称每天面对约 13 个漏洞报告，归因于 C 的内存与错误处理缺陷 [S1](https://blog.desdelinux.net/en/Rust-Linux--Greg-Kroah-Hartman--end-of-security-experiment/)；Rust 已不再被视为实验特性 [S2](https://www.i-programmer.info/news/98-languages/18527-rust-for-linux-no-longer-experimental.html) | Rust 为主体语言（ADR-004） |
| 内存安全问题占比有两种说法：约三分之二 \[S2\]，以及约 15.9%（Rust 设计上可避免的类别）[S3](https://blog.desdelinux.net/en/linux-kernel-rust-official-android-16-drivers-drm-debate/)。口径不同，不可混用 | 文档中不承诺具体比例，只承诺 unsafe 可度量（1.3） |
| 实证研究认为 Rust 能降低但不能消除内核漏洞，处理不当还带来运行时与开发成本 [S4](https://atcosdi24.sched.com/event/1fLd7/an-empirical-study-of-rust-for-linux-the-success-dissatisfaction-and-compromise) | unsafe 预算、审计、性能基线（1.3, 12） |
| CrowdStrike 事件：内核态驱动发生越界读取 [S8](https://prog.world/lessons-learned-from-the-crowdstrike-global-outage)，据报道影响约 850 万台 PC [S10](https://mspoweruser.com/microsoft-mulls-restricing-third-party-access-to-windows-kernel-after-crowdstrike-outage)；微软复盘提出减少对内核驱动的依赖 [S9](https://www.darkreading.com/application-security/microsoft-lowballs-crowdstrike-outage-impact) | 禁止第三方内核态代码、启动循环保护、驱动隔离（9） |
| 微软曾因安全厂商与欧盟监管的反对而难以收紧内核访问 [S11](https://businessof.tech/2024/07/30/microsofts-security-strategy-lessons-from-crowdstrike-outage-and-potential-kernel-access-restrictions/)；也有观点认为仅移除内核访问只能解决一小部分问题 [S7](https://www.securityweek.com/microsoft-convenes-endpoint-security-firms-following-crowdstrike-incident/amp/) | 从第一天就把“第三方扩展只能在用户态”写入政策（1.4 ADR-010） |
| Asterinas 的 framekernel 用 Rust 在内核内部做特权分离，以缩小 TCB 并兼容 Linux ABI [S12](https://arxiv.org/abs/2506.03876)；其经验是安全的驱动开发依赖安全的底层资源抽象 [S13](https://www.usenix.org/node/309439) | 首期采用“内核内 unsafe 特权分离”（2.3, 2.4） |
| Rust 系统当前的主要工作量在驱动、文件系统与 ABI 兼容 [S16](https://news.lavx.hu/article/asterinas-0-18-lands-a-rust-written-memory-safe-linux-alternative-targets-containers)；Redox 的实践表明贡献者招募对此类项目至关重要 [S19](https://www.webpronews.com/redox-os-the-rust-written-operating-system-that-refuses-to-stay-niche/) | 生态与差异化策略（15） |

### 1.2 威胁模型

| 攻击者 | 能力 | 受保护资产 | 主要对策 |
| --- | --- | --- | --- |
| 恶意用户进程 | 任意系统调用与参数 | 内核内存、其他进程 | 参数校验、SMEP/SMAP、capability、地址空间隔离 |
| 缺陷或恶意驱动 | 内核态执行或内存破坏 | 全系统完整性 | 驱动白名单与签名、unsafe 预算、驱动隔离接口、后期用户态驱动 |
| 恶意设备 | 发起任意 DMA | 物理内存 | 强制 IOMMU，设备只能访问被映射的缓冲区 |
| 恶意存储介质 | 构造畸形文件系统 | 内核解析器 | 文件系统解析器用安全 Rust、fuzz、资源上限 |
| 远程网络攻击者 | 构造畸形报文 | 网络栈 | 安全 Rust 协议解析、fuzz、速率限制 |
| 供应链攻击者 | 篡改依赖或更新包 | 构建产物、更新通道 | 依赖锁定与审查、SBOM、可复现构建、签名更新 |

**不在范围内**（首期）：具备物理接触的攻击、侧信道的完整防护（仅做主流缓解，见 11）。

### 1.3 TCB 与 unsafe 预算

规则（强制，CI 检查）：

1. `unsafe` 只允许出现在白名单 crate：`aurora-arch`、`aurora-hw`（MMIO、端口、DMA）、`aurora-mm-core`（页表与帧分配）、`aurora-ctx`（上下文切换）。
2. 其余所有 crate 在 `lib.rs` 顶部声明 `#![forbid(unsafe_code)]`。
3. 每个 `unsafe` 块必须有 `// SAFETY:` 注释，说明依赖的不变量；启用 `clippy::undocumented_unsafe_blocks`。
4. CI 统计白名单 crate 的 unsafe 块数量与行数，**增长需要评审批准**。
5. 每个发布周期做一次 unsafe 专项审计，结果归档到 `docs/security/`。

```rust
// 非白名单 crate 的 lib.rs 头部
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks, missing_docs)]
```

### 1.4 初始架构决策记录（ADR）

| 编号 | 决策 | 状态 |
| --- | --- | --- |
| ADR-001 | 使用 Rust 内置目标 `x86_64-unknown-none` 与 stable 工具链，不使用自定义目标 JSON，不依赖 nightly | 建议 |
| ADR-002 | 汇编统一使用 LLVM 集成汇编器（`.S` 文件，经 clang 编译），不引入 NASM | 建议 |
| ADR-003 | Bootloader 使用 Limine（Limine 启动协议） | 建议 |
| ADR-004 | Rust 为内核主体语言；C 仅用于确无替代的底层与兼容部分，新增 C 需评审 | 建议 |
| ADR-005 | 内核使用 `panic = abort`；panic 进入统一故障流程 | 建议 |
| ADR-006 | 首期模块静态链接，不做动态内核模块（Rust 无稳定 ABI） | 建议 |
| ADR-007 | 权限模型采用 capability（句柄）而非仅 uid | 建议 |
| ADR-008 | 所有支持 DMA 的设备必须经 IOMMU，无 IOMMU 的平台降级并告警 | 建议 |
| ADR-009 | 项目许可证与贡献协议（CLA/DCO） | **待定，阻塞商业化** |
| ADR-010 | 不提供第三方内核态扩展机制；安全软件等通过用户态事件接口接入 | 建议 |

> 对 V1.0 的更正：V1.0 与我此前的口头建议中提到“内核开发通常需要 nightly”。内置 `x86_64-unknown-none` 目标在 stable 上可用 [R5](https://doc.rust-lang.org/nightly/rustc/platform-support/x86_64-unknown-none.html)（采用前请核对该页），因此 ADR-001 选择 stable。代价是不使用不稳定特性（例如 `x86-interrupt` 调用约定），中断入口改用汇编桩（5.3）。

## 2 总体架构

### 2.1 分层与依赖方向

```text
┌──────────────────────────────────────────────────────────────────┐
│ L5 内核接口层   syscall · 对象/句柄接口 · ABI 版本               │
├──────────────────────────────────────────────────────────────────┤
│ L4 系统功能层   VFS · 文件系统 · 驱动框架 · 网络栈 · 安全 · 诊断 │
├──────────────────────────────────────────────────────────────────┤
│ L3 内核基础服务 PMM · VMM · 堆 · 调度 · 进程/线程 · 同步 · IPC   │
├──────────────────────────────────────────────────────────────────┤
│ L2 硬件抽象层   PCI · MMIO · DMA/IOMMU · 定时器 · 中断控制器     │
├──────────────────────────────────────────────────────────────────┤
│ L1 架构层       boot · CPU · GDT/IDT/TSS · APIC · 页表 · 上下文  │
└──────────────────────────────────────────────────────────────────┘
   依赖方向：只允许上层依赖下层；横向依赖必须经 trait 接口
```

### 2.2 依赖规则与自动化强制

- 低层不得依赖高层；同层模块之间只依赖对方的 `*-api` crate（只含 trait、类型、错误码）。
- 每个模块拆成 `xxx-api`（接口）与 `xxx`（实现），上层只引用 api crate，这样替换实现不影响调用者。
- 强制手段：CI 用 `cargo metadata` 生成依赖图，与 `docs/architecture/deps.toml` 中的允许清单比对，不在清单内的边直接失败；用 `cargo deny` 检查外部依赖的许可证与来源。

### 2.2.1 三层隔离的实现阶段

| 隔离层 | 含义 | 首期手段 | 后期手段 |
| --- | --- | --- | --- |
| 编译隔离 | 模块独立编译与测试 | crate 工作区、api/impl 拆分 | 同左 |
| 接口隔离 | 禁止访问对方内部状态 | `pub(crate)` 默认、`forbid(unsafe_code)`、依赖图检查 | 同左 |
| 运行隔离 | 一个模块出错不拖垮其他模块 | unsafe 特权分离、IOMMU、驱动健康监测、设备重置 | 用户态驱动、服务进程重启 |

宏内核模块默认同特权级、同地址空间，**接口隔离不等于运行隔离**。首期通过缩小 unsafe 区域与 IOMMU 获得部分运行隔离，真正的故障域隔离要等到用户态驱动阶段。

### 2.3 内核内特权分离（framekernel 思路）

把“可能破坏内存安全的操作”收敛到小的 TCB 中，其余代码全部是安全 Rust：

```text
┌───────────────────── 内核地址空间 ─────────────────────┐
│  安全 Rust 区（forbid unsafe）                          │
│   调度策略 · VFS · 文件系统 · 网络协议 · 驱动逻辑       │
│              │ 只能通过安全抽象调用                      │
│              ▼                                          │
│  TCB（允许 unsafe，体积受预算限制）                      │
│   页表 · 帧分配 · MMIO/端口 · DMA 映射 · 上下文切换     │
└─────────────────────────────────────────────────────────┘
```

这一思路来自 Asterinas 的 framekernel 与 OSTD 设计 \[S12\][S14](https://zhou-diyu.github.io/files/asterinas-atc25.pdf)，其公开材料称已支持 210 余个 Linux 系统调用并专门处理 MMIO/DMA 这类外部可修改内存。**注意**：我们借用的是架构思想，不依赖其代码，也不声称达到其形式化验证目标（相关计划见 [S21](https://hn.jakechampion.name/reader/https://lwn.net/SubscriberLink/1022920/ad60263cd13c8a13)）。

### 2.4 架构路线对比

| 方案 | 优点 | 缺点 | 本项目定位 |
| --- | --- | --- | --- |
| 加强的宏内核 | 性能好、开发快 | 驱动缺陷仍可摧毁内核 | 首期基础 |
| framekernel（内核内特权分离） | 单地址空间性能，缩小可信代码范围 | 依赖语言与抽象的正确性；较新，案例少 | **首期采用其思想** |
| 微内核（驱动在用户态） | 故障域天然隔离，Redox 采用 [S18](https://www.redox-os.org/home/) | IPC 开销与设计复杂度；真机驱动成熟度需要时间 [S17](https://doc.redox-os.org/book/our-goals.html) | 后期演进目标 |

**决策**：首期“宏内核 + 内核内特权分离”，并在驱动框架层预留“驱动运行于独立域”的接口，使后期迁移到用户态驱动不需要重写驱动逻辑（8.4）。

### 2.5 仓库与工作区

```text
aurora-os/
├── Cargo.toml                 # workspace
├── rust-toolchain.toml
├── .cargo/config.toml
├── justfile
├── boot/limine.conf
├── c/                         # 受限 C 代码（CMake）
├── kernel/
│   ├── linker.ld
│   ├── build.rs
│   └── src/main.rs            # 仅负责组装与初始化顺序
├── crates/
│   ├── aurora-arch/           # [unsafe 白名单]
│   ├── aurora-hw/             # [unsafe 白名单]
│   ├── aurora-mm-api/  aurora-mm-core/  aurora-mm/
│   ├── aurora-sched-api/  aurora-sched/
│   ├── aurora-driver-api/ aurora-driver/
│   ├── aurora-fs-api/  aurora-vfs/  aurora-fat32/
│   └── aurora-diag/           # 日志、panic、crash dump
├── tests/  tools/  docs/{architecture,adr,security,testing}/
└── userland/
```

```toml
# Cargo.toml（根）
[workspace]
resolver = "2"
members = ["kernel", "crates/*"]

[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"

[workspace.lints.clippy]
undocumented_unsafe_blocks = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "warn"

[profile.release]
panic = "abort"
lto = "thin"
codegen-units = 1
debug = "line-tables-only"

[profile.dev]
panic = "abort"
```

## 3 工具链与构建

### 3.1 版本固定

```toml
# rust-toolchain.toml —— channel 必须写成具体版本号，升级需走评审
[toolchain]
channel = "<固定的 stable 版本号>"
components = ["rust-src", "clippy", "rustfmt", "llvm-tools"]
targets = ["x86_64-unknown-none"]
```

Clang/LLVM、LLD、QEMU、OVMF 的版本同样写入 `tools/versions.toml`，CI 与本地使用同一容器镜像，保证可复现构建。

### 3.2 Cargo 配置

```toml
# .cargo/config.toml
[build]
target = "x86_64-unknown-none"

[target.x86_64-unknown-none]
rustflags = [
  "-C", "link-arg=-Tkernel/linker.ld",
  "-C", "force-frame-pointers=yes",   # 便于栈回溯
]
```

内置目标的默认设置（禁用红区、软浮点、kernel 代码模型等）以 \[R5\] 平台支持页为准，**不要在未核对前手写覆盖**。内核内禁用 SSE/x87 以避免在中断路径保存浮点状态；用户线程的 FPU/SIMD 状态由上下文切换按需保存（5.4）。

### 3.3 链接脚本（higher-half，段权限满足 W^X）

```text
/* kernel/linker.ld */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS {
  text   PT_LOAD FLAGS(5);   /* R+X */
  rodata PT_LOAD FLAGS(4);   /* R   */
  data   PT_LOAD FLAGS(6);   /* R+W */
}

SECTIONS {
  . = 0xffffffff80000000;

  .text : { *(.text .text.*) } :text
  . = ALIGN(4K);
  .rodata : { *(.rodata .rodata.*) } :rodata
  . = ALIGN(4K);
  .requests : {
    KEEP(*(.requests_start_marker))
    KEEP(*(.requests))
    KEEP(*(.requests_end_marker))
  } :rodata
  . = ALIGN(4K);
  .data : { *(.data .data.*) } :data
  .bss  : { *(.bss .bss.*) *(COMMON) } :data

  /DISCARD/ : { *(.eh_frame*) *(.note .note.*) }
}
```

链接脚本与 Limine 协议的段要求以 Limine 官方文档与模板为准 [R3](https://github.com/limine-bootloader/limine)。

### 3.4 C 代码与 Rust 的集成（ADR-004 的执行方式）

C 代码由 CMake 编译成静态库，Cargo 在 `build.rs` 中链接：

```cmake
# c/CMakeLists.txt
add_library(aurora_c STATIC src/early.c src/asm/entry.S)
target_compile_options(aurora_c PRIVATE
  --target=x86_64-unknown-none-elf -ffreestanding -fno-stack-protector
  -mno-red-zone -mno-sse -mno-mmx -mcmodel=kernel -fno-pic
  -Wall -Wextra -Werror)
```

```rust
// kernel/build.rs
fn main() {
    let dir = std::env::var("AURORA_C_LIB_DIR").expect("set by justfile");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static=aurora_c");
    println!("cargo:rerun-if-changed=../c");
}
```

新增 C 文件须在评审单中说明“为何不能用 Rust”，C 代码量作为指标长期追踪，目标是只减不增。

### 3.5 统一命令入口

```text
# justfile（节选）
build:    cmake --build build/c && cargo build --release
image:    build && tools/image/make_image.sh
run:      image && qemu-system-x86_64 -M q35 -m 512M -smp 4 \
            -bios $OVMF -drive format=raw,file=aurora.img \
            -serial stdio -display none -no-reboot -no-shutdown \
            -device isa-debug-exit,iobase=0xf4,iosize=0x04
test:     cargo test --workspace --lib && tools/qemu_tests.sh
lint:     cargo fmt --check && cargo clippy --workspace -- -D warnings
```

OVMF 固件路径随发行版不同，由环境变量 `OVMF` 提供。

## 4 启动流程

### 4.1 启动链路

```text
UEFI 固件 ─▶ Limine（读 limine.conf、加载内核 ELF、建立 higher-half 与直接映射、传递启动信息）
      │
      ▼
  kmain（已处于长模式、已开分页、栈由 Limine 提供）
      │
      ▼
 Stage0  串口 → 日志 → 校验启动信息          （无堆、无锁、单核）
 Stage1  CPU 特性检测 → GDT/TSS/IDT          （无堆）
 Stage2  内存图解析 → PMM → VMM 接管页表 → 内核堆
 Stage3  ACPI 解析 → APIC/定时器 → 调度器 → 启动其他 CPU
 Stage4  PCI 枚举 → IOMMU → 驱动框架 → 存储 → VFS
 Stage5  用户态接口（syscall、第一个用户进程）
```

Bootloader 只负责加载与传参，不承担策略逻辑。Limine 的请求/响应机制与配置项以官方文档为准 [R3](https://github.com/limine-bootloader/limine)。

### 4.2 初始化阶段约束

| 阶段 | 可用能力 | 禁止 |
| --- | --- | --- |
| Stage0–1 | 静态缓冲区、串口 | 堆分配、锁等待、线程 |
| Stage2 | PMM（堆就绪前仅用静态元数据） | 依赖堆的类型 |
| Stage3–4 | 堆、锁、定时器 | 阻塞等待尚未存在的调度器 |
| Stage5 | 全部内核基础服务 | — |

每个阶段的失败都必须输出阶段名与错误码，并进入统一故障流程（9）。

### 4.3 Limine 请求与内核入口

```rust
// kernel/src/boot.rs —— 示意骨架：limine crate 的 API 以固定版本文档为准
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker,
    RsdpRequest,
};
use limine::BaseRevision;

#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();
#[used]
#[link_section = ".requests"]
static MEMMAP: MemoryMapRequest = MemoryMapRequest::new();
#[used]
#[link_section = ".requests"]
static HHDM: HhdmRequest = HhdmRequest::new();
#[used]
#[link_section = ".requests"]
static RSDP: RsdpRequest = RsdpRequest::new();
#[used]
#[link_section = ".requests"]
static FB: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".requests_start_marker"]
static START: RequestsStartMarker = RequestsStartMarker::new();
#[used]
#[link_section = ".requests_end_marker"]
static END: RequestsEndMarker = RequestsEndMarker::new();

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    // 启动信息不被支持时无法继续：尽早失败并输出诊断
    if !BASE_REVISION.is_supported() {
        aurora_diag::early_fatal("boot: unsupported Limine base revision");
    }
    let Some(hhdm) = HHDM.get_response() else {
        aurora_diag::early_fatal("boot: missing HHDM response");
    };
    let Some(memmap) = MEMMAP.get_response() else {
        aurora_diag::early_fatal("boot: missing memory map");
    };
    let info = crate::init::BootInfo::from_limine(hhdm, memmap, RSDP.get_response(), FB.get_response());
    crate::init::run_all_stages(info)
}
```

### 4.4 初始化编排

```rust
// kernel/src/init.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage { Serial, Cpu, Memory, Interrupts, Sched, Devices, Userland }

pub struct InitError { pub stage: Stage, pub code: aurora_diag::ErrorCode }

type StageFn = fn(&BootInfo) -> Result<(), aurora_diag::ErrorCode>;

const STAGES: &[(Stage, StageFn)] = &[
    (Stage::Serial,     stage_serial),
    (Stage::Cpu,        stage_cpu),
    (Stage::Memory,     stage_memory),
    (Stage::Interrupts, stage_interrupts),
    (Stage::Sched,      stage_sched),
    (Stage::Devices,    stage_devices),
    (Stage::Userland,   stage_userland),
];

pub fn run_all_stages(info: BootInfo) -> ! {
    for (stage, f) in STAGES {
        aurora_diag::log_info!("init: stage {:?} begin", stage);
        if let Err(code) = f(&info) {
            // 统一进入故障流程，不允许带着未完成的阶段继续
            aurora_diag::fatal(InitError { stage: *stage, code });
        }
        aurora_diag::log_info!("init: stage {:?} ok", stage);
    }
    crate::sched::enter_idle_loop()
}
```

规则：阶段顺序在一处声明；模块不得自行“悬挂”初始化到其他位置。模块销毁顺序为初始化顺序的逆序。

### 4.5 早期串口日志（首个可观测能力）

```rust
// crates/aurora-hw/src/port.rs —— unsafe 白名单 crate
pub struct Port8(u16);
impl Port8 {
    pub const fn new(p: u16) -> Self { Self(p) }
    pub fn write(&self, v: u8) {
        // SAFETY: 调用者通过平台表获得端口号；I/O 写不访问内存，不违反 Rust 内存模型。
        unsafe { core::arch::asm!("out dx, al", in("dx") self.0, in("al") v, options(nomem, nostack, preserves_flags)); }
    }
    pub fn read(&self) -> u8 {
        let v: u8;
        // SAFETY: 同上。
        unsafe { core::arch::asm!("in al, dx", in("dx") self.0, out("al") v, options(nomem, nostack, preserves_flags)); }
        v
    }
}
```

串口（16550）初始化与发送循环的寄存器细节参考 OSDev 指南 [R6](https://wiki.osdev.org/)。日志必须带级别、CPU 号、单调时间戳，并支持环形缓冲以便 crash dump 读取。

## 5 CPU 与中断

### 5.1 CPU 特性检测与最低要求

内核启动时检测并记录 CPU 特性，不满足“必需”项则拒绝启动，“可选”项决定使用哪一条实现路径。

| 类别 | 特性 | 缺失时 |
| --- | --- | --- |
| 必需 | long mode、NX、SYSCALL/SYSRET、APIC、原子指令 | 拒绝启动并输出原因 |
| 强烈建议 | SMEP、SMAP、XSAVE | 告警，取消商业版支持声明 |
| 可选 | PCID、x2APIC、INVPCID、RDRAND/RDSEED、1 GiB 大页 | 回退到通用路径 |

```rust
// crates/aurora-arch/src/cpuid.rs
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub nx: bool, pub smep: bool, pub smap: bool, pub pcid: bool,
    pub x2apic: bool, pub xsave: bool, pub rdrand: bool,
}

pub fn detect() -> CpuFeatures {
    // SAFETY: CPUID 在 x86-64 上总是可用，且无副作用。
    let l1 = unsafe { core::arch::x86_64::__cpuid(1) };
    let l7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };
    let ext = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) };
    CpuFeatures {
        nx:     ext.edx & (1 << 20) != 0,
        smep:   l7.ebx & (1 << 7)  != 0,
        smap:   l7.ebx & (1 << 20) != 0,
        pcid:   l1.ecx & (1 << 17) != 0,
        x2apic: l1.ecx & (1 << 21) != 0,
        xsave:  l1.ecx & (1 << 26) != 0,
        rdrand: l1.ecx & (1 << 30) != 0,
    }
}
```

位位置以 Intel SDM 与 AMD APM 的 CPUID 章节为准 [R1](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)，代码中的位号需在评审时逐项核对。通用内核代码只依赖 `CpuFeatures`，不得依赖具体 CPU 型号。

### 5.2 GDT、TSS 与 IST

| IST 项 | 用途 | 要求 |
| --- | --- | --- |
| IST1 | Double Fault | 独立栈 + guard page |
| IST2 | NMI | 独立栈 |
| IST3 | Machine Check | 独立栈 |
| RSP0 | 用户态进入内核 | 每线程独立内核栈 |

每个 CPU 拥有自己的 GDT、TSS 与异常栈（保存在 CPU-local 区域），栈之间用不可访问的页隔开，避免栈溢出惄悄改写相邻数据。可使用 rust-osdev 的 `x86_64` crate 提供的类型 [R7](https://github.com/rust-osdev/x86_64)，但需固定版本并审查其 unsafe。

```rust
// crates/aurora-arch/src/gdt.rs —— 示意骨架
pub const DOUBLE_FAULT_IST: u16 = 0;   // 对应 IST1（库内索引从 0 计，以所用版本为准）

pub struct CpuTables {
    tss: x86_64::structures::tss::TaskStateSegment,
    gdt: x86_64::structures::gdt::GlobalDescriptorTable,
    selectors: Selectors,
}

impl CpuTables {
    /// 为当前 CPU 创建表；三个异常栈由调用方在 Stage2 后分配并传入。
    pub fn new(df_stack_top: VirtAddr, nmi_stack_top: VirtAddr, mc_stack_top: VirtAddr) -> Self { /* ... */ }
    /// SAFETY: 必须在该 CPU 上只调用一次，且 `self` 在 CPU 生命周期内不被移动或释放。
    pub unsafe fn load(&'static self) { /* lgdt, ltr, reload segments */ }
}
```

### 5.3 中断入口（汇编桩）

由于 ADR-001 不使用 nightly 的 `x86-interrupt` 调用约定，所有向量走统一的汇编桩，再进入 Rust 分发函数。汇编量保持最小，只做保存现场、调用、恢复。

```rust
// crates/aurora-arch/src/trap.rs
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64,  pub r8: u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    pub vector: u64, pub error_code: u64,
    pub rip: u64, pub cs: u64, pub rflags: u64, pub rsp: u64, pub ss: u64,
}

core::arch::global_asm!(r#"
.macro ISR_NOERR vec
.global isr_\\vec
isr_\\vec:
    push 0
    push \\vec
    jmp isr_common
.endm
.macro ISR_ERR vec
.global isr_\\vec
isr_\\vec:
    push \\vec
    jmp isr_common
.endm

isr_common:
    // 来自用户态（CS 低 2 位不为 0）时必须 swapgs，请见 10.1 的入口不变量
    test qword ptr [rsp + 24], 3
    jz 1f
    swapgs
1:
    push rax; push rbx; push rcx; push rdx; push rsi; push rdi; push rbp
    push r8;  push r9;  push r10; push r11
    push r12; push r13; push r14; push r15
    mov rdi, rsp
    cld
    call interrupt_dispatch
    pop r15; pop r14; pop r13; pop r12
    pop r11; pop r10; pop r9;  pop r8
    pop rbp; pop rdi; pop rsi; pop rdx; pop rcx; pop rbx; pop rax
    add rsp, 16
    test qword ptr [rsp + 8], 3
    jz 2f
    swapgs
2:
    iretq

ISR_NOERR 0
ISR_NOERR 6
ISR_ERR   8
ISR_ERR   13
ISR_ERR   14
// ... 其余向量由构建脚本生成
"#);

#[no_mangle]
extern "C" fn interrupt_dispatch(frame: &mut TrapFrame) {
    crate::irq::enter();                    // 标记进入中断上下文
    match frame.vector {
        14 => crate::fault::page_fault(frame),
        8  => crate::fault::double_fault(frame),   // 走 IST，不可恢复
        v  => crate::irq::dispatch(v as u8, frame),
    }
    crate::irq::exit();
}
```

汇编语法采用 Intel 语法（Rust `global_asm!` 默认），`.S` 文件内使用 `.intel_syntax noprefix`，保持全项目一致（ADR-002）。**评审要点**：栈对齐、向量 8/10/11/12/13/14/17/21 的错误码表、来自用户态时的 `swapgs`、NMI 与机器检查的重入性都必须有独立测试。异常向量与错误码语义以 Intel SDM 第 3 卷为准 \[R1\]。

### 5.4 FPU/SIMD 状态

- 内核代码使用软浮点，不触碰 x87/SSE/AVX，因此中断入口不保存浮点状态。
- 用户线程在上下文切换时按 XSAVE（若支持）保存扩展状态，状态区大小从 CPUID 枚举获得，不硬编码。
- 如需在内核里使用 SIMD（例如加密），必须用 RAII 守卫显式保存和恢复。

### 5.5 中断上下文约束

| 规则 | 强制方式 |
| --- | --- |
| 不得阻塞、不得睡眠 | 阻塞原语内部 `debug_assert!(!irq::in_irq())`，测试环境下违反即 panic |
| 不得使用普通堆分配 | 中断上下文只能使用预留的原子池 |
| 不得持有可睡眠锁 | 锁类型区分 `IrqSpinLock` 与普通锁（见 7） |
| 复杂工作下半部 | 投递到延迟工作队列，由内核线程执行 |
| 中断风暴防护 | 每设备中断率统计，超限则屏蔽该设备中断并触发二级故障（9） |

### 5.6 异常处理策略

| 异常 | 来自用户态 | 来自内核态 |
| --- | --- | --- |
| #PF 页错误 | 合法则补页，否则终止进程 | 仅 `copy_*_user` 路径允许并恢复，其余为四级故障 |
| #GP、#UD、#DE | 终止进程 | 四级故障 |
| #DF | — | 四级故障（IST 栈上输出现场） |
| NMI | — | 记录后按来源处理（watchdog 或硬件错误） |
| #MC | — | 记录 MCA 信息，按严重程度分级 |

## 6 内存管理

### 6.1 地址空间布局（示例，非定案）

```text
0x0000_0000_0000_0000 ── 0x0000_7FFF_FFFF_FFFF   用户空间（47 位地址）
         … 非规范地址空洞 …
0xFFFF_8000_0000_0000 ── …                     直接映射（HHDM，偏移以 Limine 响应为准，不硬编码）
0xFFFF_A000_0000_0000 ── …                     内核堆
0xFFFF_B000_0000_0000 ── …                     MMIO 映射区
0xFFFF_C000_0000_0000 ── …                     CPU-local 区
0xFFFF_FFFF_8000_0000 ── …                     内核镜像（higher-half，W^X）
```

内核镜像 KASLR 的支持与开关以 Limine 配置文档为准 \[R3\]。非内核代码不得依赖上述具体数值，只通过 `aurora-mm-api` 获取区域。

### 6.2 分层

```text
Boot Memory Map ─▶ Boot Allocator（一次性、只增不减）
                          │ 移交
                          ▼
        PMM（伙伴/位图，按 order 分配） ── 统计、毒化、所有权标签
                          │
                          ▼
        VMM（页表、映射、权限、TLB 管理）
                          │
                          ▼
        内核堆（slab 大小类，建立在 VMM 之上）
```

### 6.3 接口与所有权

```rust
// crates/aurora-mm-api/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MmError {
    OutOfMemory, InvalidAddress, Misaligned, AlreadyMapped, NotMapped,
    PermissionDenied, DoubleFree, WxViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// 拒绝非规范地址：高 17 位必须与第 47 位相同。
    pub fn new(a: u64) -> Result<Self, MmError> {
        let top = a >> 47;
        if top == 0 || top == 0x1_FFFF { Ok(Self(a)) } else { Err(MmError::InvalidAddress) }
    }
    pub const fn as_u64(self) -> u64 { self.0 }
}

/// 模块标识，用于资源所有权追踪（9.1 资源模型）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleId(pub u16);

/// 拥有一段物理页的 RAII 句柄：丢弃即释放，类型系统保证不重复释放。
pub struct OwnedFrames { base: PhysAddr, order: u8, owner: ModuleId }

impl OwnedFrames {
    pub fn base(&self) -> PhysAddr { self.base }
    pub fn order(&self) -> u8 { self.order }
    pub fn owner(&self) -> ModuleId { self.owner }
}

impl Drop for OwnedFrames {
    fn drop(&mut self) {
        // 释放路径由实现 crate 注册；重复释放在分配器内部由状态位检测并记录 MmError::DoubleFree
        crate::registry::release(self.base, self.order, self.owner);
    }
}

pub trait FrameAllocator: Sync {
    fn alloc(&self, order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError>;
    fn stats(&self) -> FrameStats;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode { WriteBack, Uncacheable, WriteCombining }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags { writable: bool, executable: bool, user: bool, cache: CacheMode }

impl PageFlags {
    /// W^X 在构造时强制：同时可写与可执行直接失败。
    pub fn new(w: bool, x: bool, user: bool, cache: CacheMode) -> Result<Self, MmError> {
        if w && x { return Err(MmError::WxViolation); }
        Ok(Self { writable: w, executable: x, user, cache })
    }
}

pub trait AddressSpace {
    fn map(&mut self, va: VirtAddr, frames: &OwnedFrames, flags: PageFlags) -> Result<(), MmError>;
    fn unmap(&mut self, va: VirtAddr, pages: usize) -> Result<(), MmError>;
    fn query(&self, va: VirtAddr) -> Result<(PhysAddr, PageFlags), MmError>;
}
```

`FrameStats`、`registry` 等辅助类型按相同风格定义，略。设计核心是：**地址类型不可混用、页权限不可非法构造、物理页所有权由 RAII 表达**。

### 6.4 权限与保护不变量

- 任何页不同时可写与可执行（W^X）；内核镜像代码段只读可执行，只读数据段不可执行，其余不可执行。
- 用户页在内核态不可执行（SMEP）、默认不可访问（SMAP），只有 `copy_*_user` 路径用 STAC/CLAC 短暂开放（10.3）。
- 所有内核栈、异常栈、堆区头尾都有 guard page。
- 内核空间映射只由 VMM 创建，其他模块通过 `AddressSpace` 接口申请。

### 6.5 内核堆与 OOM 策略

- 内核堆基于 slab 大小类，页来自 VMM；每次分配可带模块标签（调试构建下记录 `#[track_caller]` 位置）。
- **禁止隐式 OOM 崩溃**：在稳定版 Rust 上，使用全局分配器的普通分配失败会进入 alloc 错误处理而终止。内核代码应使用可失败分配（如 `Vec::try_reserve`）或 `aurora-alloc` 提供的 `try_*` 封装，并把失败作为三级资源错误向上传播（9）。该点作为代码评审清单项，并用故障注入测试覆盖（12）。
- 中断上下文只能使用预留原子池（见 5.5）。

### 6.6 多核 TLB 一致性

修改或撤销映射后需对所有可能缓存该映射的 CPU 做 TLB shootdown（IPI）。VMM 记录每个地址空间正在运行的 CPU 集合，仅向该集合发送。支持 PCID 时用 PCID 减少全刷。解映射过程必须等待 shootdown 完成后才释放物理页。

### 6.7 内存诊断

| 能力 | 实现 | 阶段 |
| --- | --- | --- |
| 重复释放检测 | PMM 状态位 + RAII | M2 |
| 释放后毒化填充 | 调试构建下释放时填充固定字节 | M2 |
| 泄漏报告 | 按模块标签汇总存活分配 | M2 |
| 堆越界 canary | slab 头尾 canary | M3 |
| 类 ASan 影子内存 | 评估后再决定 | 后期 |

## 7 并发与调度

### 7.1 锁规则与锁序

- 所有锁必须声明**锁等级（rank）**，获取锁时等级必须严格递增，调试构建用锁依赖检查器（lockdep 思路）在运行时断言。
- 进入中断可能再次获取的锁，必须使用 `IrqSpinLock`（获取时关中断）。
- 持锁期间禁止：睡眠、堆分配（除非该锁标记为可分配）、调用未知回调。
- 锁等级表维护在 `docs/architecture/lock-order.md`，新增锁必须先更新该表。
- `aurora-sync` 加入 unsafe 白名单（对 1.3 的补充）。

```rust
// crates/aurora-sync/src/irq_spin.rs —— unsafe 白名单 crate
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockRank(pub u8);

pub struct IrqSpinLock<T> {
    locked: AtomicBool,
    rank: LockRank,
    data: UnsafeCell<T>,
}

// SAFETY: 访问 `data` 只能在持有 `locked` 时进行，因此 T: Send 即可跨 CPU 共享。
unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

pub struct IrqGuard<'a, T> { lock: &'a IrqSpinLock<T>, irq_was_enabled: bool }

impl<T> IrqSpinLock<T> {
    pub const fn new(rank: LockRank, v: T) -> Self {
        Self { locked: AtomicBool::new(false), rank, data: UnsafeCell::new(v) }
    }

    pub fn lock(&self) -> IrqGuard<'_, T> {
        let irq_was_enabled = aurora_arch::irq_save();   // 先关中断，再自旋
        crate::lockdep::on_acquire(self.rank);           // 调试构建：等级必须递增
        while self.locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        IrqGuard { lock: self, irq_was_enabled }
    }
}

impl<T> core::ops::Deref for IrqGuard<'_, T> {
    type Target = T;
    // SAFETY: 守卫存在期间独占锁。
    fn deref(&self) -> &T { unsafe { &*self.lock.data.get() } }
}
impl<T> core::ops::DerefMut for IrqGuard<'_, T> {
    // SAFETY: 同上，且守卫不可克隆，不会出现别名的可变引用。
    fn deref_mut(&mut self) -> &mut T { unsafe { &mut *self.lock.data.get() } }
}

impl<T> Drop for IrqGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        crate::lockdep::on_release(self.lock.rank);
        aurora_arch::irq_restore(self.irq_was_enabled);
    }
}
```

内存序规则：同步原语用 Acquire/Release；`Relaxed` 只用于纯统计计数器；每个原子操作需在注释中说明为什么该序足够。

### 7.2 调度策略与上下文切换分离

```rust
// crates/aurora-sched-api/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState { New, Ready, Running, Blocked, Zombie }

pub struct ThreadId(pub u64);

/// 策略只决定“下一个运行谁”，不碰寄存器、不碰页表。
pub trait SchedPolicy: Send {
    fn enqueue(&mut self, t: ThreadId, prio: u8);
    fn dequeue(&mut self, t: ThreadId);
    fn pick_next(&mut self) -> Option<ThreadId>;
    fn on_tick(&mut self, running: ThreadId) -> bool;   // 返回 true 表示需要抢占
}
```

```rust
// crates/aurora-ctx/src/switch.rs —— 上下文切换（unsafe 白名单）
core::arch::global_asm!(r#"
.global switch_context
switch_context:            // rdi = &mut old_rsp, rsi = new_rsp
    push rbp; push rbx; push r12; push r13; push r14; push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15; pop r14; pop r13; pop r12; pop rbx; pop rbp
    ret
"#);

extern "C" { fn switch_context(old_rsp: *mut u64, new_rsp: u64); }
```

设计要点：只保存被调用者保存寄存器（System V ABI）；切换地址空间（写 CR3）、切换用户 FPU 状态、更新 TSS RSP0 都在 Rust 侧完成，再调用汇编。新线程的栈预先摆好“寄存器初值 + 入口蹦板地址”，使 `ret` 跳进蹦板。

### 7.3 调度与 SMP 策略

- 首期：单核抢占式优先级调度先稳定；SMP 拆为独立里程碑（见 14），避免 V1.0 中 M3 一次交付多线程、调度和 SMP 的风险。
- SMP：每 CPU 独立运行队列，跨 CPU 迁移用 IPI，负载均衡由低频任务完成。
- 混合架构 CPU（性能核/能效核）的调度提示依赖平台提供的核心类型信息，列入 13 的真机阶段。

### 7.4 并发正确性验证

- `loom` 对锁和原子逻辑做穷举交错测试（在宿主机上运行纯逻辑部分）；内核集成测试用 QEMU 多核压力运行。
- 每个共享状态写明“由哪把锁保护”。

## 8 驱动与设备模型

### 8.1 设备模型

```text
 Bus（PCI/ACPI/虚拟） ──枚举──▶ Device（id、资源、状态）
                                    │ 匹配 id 表
                                    ▼
                               Driver（状态机）
                                    │ 只能通过
                                    ▼
                            DriverCtx（能力句柄集合）
                 MMIO · DMA · IRQ · 定时器 · 日志 · 内存预算
```

### 8.2 驱动生命周期

```text
Registered ─▶ Probing ─▶ Running ─▶ Stopping ─▶ Stopped ─▶ Unregistered
                 │            │                                  ▲
                 │            └──▶ Resetting ──▶ Running（恢复成功）
                 └──────────┴──────▶ Quarantined（超过重试预算，撤销全部资源）
```

```rust
// crates/aurora-driver-api/src/lib.rs
#![no_std]
#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    Registered, Probing, Running, Resetting, Stopping, Stopped, Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health { Ok, Degraded, Failed }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DriverError { NoDevice, Timeout, Io, ResourceExhausted, Unsupported, Internal }

pub trait Driver: Send {
    fn probe(&mut self, dev: &DeviceInfo, ctx: &mut dyn DriverCtx) -> Result<(), DriverError>;
    fn start(&mut self, ctx: &mut dyn DriverCtx) -> Result<(), DriverError>;
    fn stop(&mut self, ctx: &mut dyn DriverCtx);
    /// 将设备重置回已知状态；失败则上层将驱动隔离。
    fn reset(&mut self, ctx: &mut dyn DriverCtx) -> Result<(), DriverError>;
    fn health(&self) -> Health;
}

/// 驱动能触达内核的全部途径。不允许原始指针、不允许物理地址。
pub trait DriverCtx {
    fn map_mmio(&mut self, bar: u8) -> Result<MmioHandle, DriverError>;
    fn alloc_dma(&mut self, len: usize) -> Result<DmaHandle, DriverError>;
    fn request_irq(&mut self, line: IrqLine, h: IrqHandlerFn) -> Result<IrqHandle, DriverError>;
    fn set_timer(&mut self, ms: u32, cb: TimerFn) -> Result<TimerHandle, DriverError>;
    fn log(&self, level: LogLevel, msg: &str);
}
```

### 8.3 安全的 MMIO 与 DMA 抽象

Asterinas 团队总结的经验是，安全的驱动开发需要安全的底层资源抽象 [S13](https://www.usenix.org/node/309439)，并专门处理了 MMIO/DMA 这类可被外部修改的内存 [S14](https://zhou-diyu.github.io/files/asterinas-atc25.pdf)。下面是我们的对应设计：**DMA 缓冲区不暴露为 `&[u8]`/`&mut [u8]`**（设备随时可能写入，这会造成语言层面的未定义行为），只提供 volatile 访问器。

```rust
// crates/aurora-hw/src/mmio.rs —— unsafe 白名单 crate
pub struct MmioRegion { base: *mut u8, len: usize }

impl MmioRegion {
    /// SAFETY: [base, base+len) 必须是已经由 VMM 以 Uncacheable 映射的设备窗口，
    /// 且在本对象生命周期内保持映射。
    pub(crate) unsafe fn new(base: *mut u8, len: usize) -> Self { Self { base, len } }

    pub fn read32(&self, off: usize) -> Result<u32, HwError> {
        self.check(off, 4)?;
        // SAFETY: check 保证对齐且在映射范围内。
        Ok(unsafe { core::ptr::read_volatile(self.base.add(off) as *const u32) })
    }
    pub fn write32(&self, off: usize, v: u32) -> Result<(), HwError> {
        self.check(off, 4)?;
        // SAFETY: 同上。
        unsafe { core::ptr::write_volatile(self.base.add(off) as *mut u32, v) };
        Ok(())
    }
    fn check(&self, off: usize, w: usize) -> Result<(), HwError> {
        if off % w != 0 || off.checked_add(w).map_or(true, |e| e > self.len) {
            return Err(HwError::OutOfBounds);
        }
        Ok(())
    }
}
```

```rust
// crates/aurora-hw/src/dma.rs
pub struct DmaBuffer {
    frames: OwnedFrames,      // 物理页所有权
    cpu_ptr: *mut u8,         // 内核侧映射
    bus: BusAddr,             // 设备看到的 IOVA（经 IOMMU）
    domain: IommuDomainId,
    len: usize,
}

impl DmaBuffer {
    pub fn bus_addr(&self) -> BusAddr { self.bus }
    pub fn len(&self) -> usize { self.len }

    pub fn read_u32(&self, off: usize) -> Result<u32, HwError> { /* check + read_volatile */ todo!() }
    pub fn write_u32(&self, off: usize, v: u32) -> Result<(), HwError> { /* check + write_volatile */ todo!() }
    pub fn copy_out(&self, off: usize, dst: &mut [u8]) -> Result<(), HwError> { /* volatile 逐字节拷贝 */ todo!() }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // 顺序不可颠倒：先撤销 IOMMU 映射并等待 IOTLB 刷新，再让 `frames` 被释放，
        // 否则设备可能继续写入已被重新分配给别人的页。
        iommu::unmap_and_flush(self.domain, self.bus, self.len);
    }
}
```

`todo!()` 标记的方法体略去。注意 `todo!()` 会 panic，正式代码中禁止保留。

### 8.4 IOMMU 策略（ADR-008）

- 平台通过 ACPI 的 DMAR（Intel VT-d）或 IVRS（AMD-Vi）表提供 IOMMU 信息，表格式以 ACPI 与厂商 IOMMU 规范为准 [R2](https://uefi.org/acpi/specs)（本次未核验）。
- 每个设备（或隔离组）一个域，设备只能访问被显式映射的缓冲区。
- 无 IOMMU 的平台：启动时告警，只允许使用从低端内存分配的“弹跳缓冲区”，并在商业版支持声明中标明隔离能力降级。
- 驱动被隔离（Quarantined）时，立即撤销其 IOMMU 域与 MMIO 映射，阻止失控设备继续访问内存。

### 8.5 为用户态驱动预留的接口形态

`DriverCtx` 是驱动与内核之间唯一的接口，驱动不持有原始指针。首期由内核内实现直接支撑，后期同一组 trait 可由“系统调用代理”支撑，驱动代码无需改动即可迁移到用户态：

```text
          驱动逻辑（同一份代码）
                │ DriverCtx
      ┌────────┴────────┐
      ▼                 ▼
 内核内实现（首期）   系统调用代理（后期，用户态驱动）
 直接映射 MMIO/DMA    经 capability 授权的 MMIO/DMA/IRQ 句柄
```

这样的迁移路径与 Redox 的“驱动运行在用户态”思路一致 [S18](https://www.redox-os.org/home/)，但我们不在首期承担它的 IPC 与性能代价。

### 8.6 驱动优先级

| 优先级 | 驱动 | 理由 |
| --- | --- | --- |
| P0 | 串口、Framebuffer（Limine 提供）、定时器 | 可观测性 |
| P1 | virtio-blk / virtio-net | 在 QEMU 中低成本验证驱动框架 |
| P2 | NVMe、xHCI + USB HID | 现代 PC 的存储与输入 |
| P3 | AHCI、常见有线网卡 | 兼容性 |
| 后期 | Wi-Fi、GPU、音频 | 工作量大，依赖生态策略（15） |

### 8.7 设备枚举

PCIe 配置空间通过 ACPI MCFG 表的 ECAM 访问；MSI/MSI-X 优先于传统引脚中断；BAR 映射一律由 `DriverCtx::map_mmio` 经边界检查后提供。

## 9 故障隔离与可靠性

### 9.1 资源模型

每个内核资源（物理页、堆对象、IRQ、DMA 映射、设备、句柄等）登记到统一的资源表，模块故障时可按所有者一次性撤销。

```rust
// crates/aurora-resource-api/src/lib.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind { PhysFrames, HeapObject, IrqLine, DmaMapping, MmioMapping, Device, Handle }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState { Live, Revoked, Released }

pub struct ResourceRecord {
    pub id: u64,
    pub kind: ResourceKind,
    pub owner: ModuleId,        // 当前所有者
    pub creator: ModuleId,      // 创建者
    pub created_tick: u64,
    pub state: ResourceState,
}

pub trait ResourceRegistry: Sync {
    fn register(&self, kind: ResourceKind, owner: ModuleId) -> Result<u64, ResError>;
    fn transfer(&self, id: u64, new_owner: ModuleId) -> Result<(), ResError>;
    /// 故障恢复：撤销某模块名下的全部存活资源（先撤销 IOMMU/MMIO，再释放内存）。
    fn revoke_all(&self, owner: ModuleId) -> RevokeReport;
}
```

### 9.2 四级故障与升级规则

```text
 L1 可恢复错误  ── 返回 Result，调用者处理
   │ 重复超限
   ▼
 L2 模块错误    ── 停止该模块→设备重置→重新初始化（有重试预算）
   │ 重置失败 / 预算用尽
   ▼
 L3 资源错误    ── 隔离模块（Quarantined）、撤销其全部资源、限制相关操作
   │ 完整性可能已被破坏
   ▼
 L4 完整性错误  ── 停止其他 CPU、保存现场、Crash Dump、重启或停机
```

```rust
// crates/aurora-diag/src/fault.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaultLevel { Recoverable = 1, Module = 2, Resource = 3, Integrity = 4 }

pub struct FaultReport {
    pub level: FaultLevel,
    pub module: ModuleId,
    pub code: ErrorCode,
    pub cpu: u32,
}

pub fn handle(r: FaultReport, budget: &mut RetryBudget) -> Action {
    match r.level {
        FaultLevel::Recoverable => Action::ReturnError,
        FaultLevel::Module if budget.try_consume(r.module) => Action::ResetModule(r.module),
        FaultLevel::Module | FaultLevel::Resource => Action::Quarantine(r.module),
        FaultLevel::Integrity => Action::Panic,
    }
}
```

### 9.3 诚实的能力边界

- `panic = abort`（ADR-005）意味着 **panic 永远是系统级故障**，不能靠“捕获 panic”来局部恢复。可恢复的驱动错误必须通过 `Result`、超时检测与设备重置表达。
- **不支持**在内核态中途强杀某个驱动线程并继续运行：它可能持有锁或留下不一致的内部状态。L3 的隔离是“撤销它能触及的资源，让卡住的线程留在泄漏状态”，而不是继续执行它。
- 内存破坏类错误（例如 TCB 内的 unsafe 缺陷）属于 L4。这正是 CrowdStrike 事件中内核态驱动越界访问后内核必须停机的原因；微软侧也有观点认为这种情况下内核失败是预期且安全的行为 [S6](https://www.techtarget.com/it-infrastructure/news/366599066/Microsoft-SecOps-pros-weigh-kernel-access-post-CrowdStrike)。因此重点不是“避免停机”，而是“停机后能自动恢复到可用状态”（9.4、9.5）。

### 9.4 启动循环保护与安全模式

```text
 启动 ─▶ 读取“连续失败启动计数” n
          │
          ├─ n ≥ 阈值 ─▶ 安全模式：仅加载必要驱动、忽略第三方配置
          └─ 否则 ─▶ 正常启动
          │
          写入 n+1 ─▶ 运行……达到“健康”条件（Stage5 完成且稳定一段时间）
                                │
                                ▼
                          计数清零，标记当前槽位为 good
```

```rust
// kernel/src/boot_guard.rs
pub enum BootMode { Normal, Safe }

pub fn decide_boot_mode(store: &mut dyn BootStateStore, max_failures: u32) -> BootMode {
    let n = store.failed_boots().unwrap_or(max_failures);  // 读不到就按最坏情况处理
    let _ = store.set_failed_boots(n.saturating_add(1));    // 先计数，再进入可能崩溃的路径
    if n >= max_failures { BootMode::Safe } else { BootMode::Normal }
}

pub fn mark_boot_healthy(store: &mut dyn BootStateStore) {
    let _ = store.set_failed_boots(0);
    let _ = store.mark_current_slot_good();
}
```

计数与隔离名单的持久化位置（UEFI 变量还是 ESP 上的文件）是待定决策 **ADR-011**，需结合 UEFI 运行时服务的可用性评估 \[R2\]。安全模式下连续崩溃的驱动会被写入隔离名单，下次启动自动跳过。

### 9.5 A/B 更新与回滚

```text
  槽位 A（当前 good）          槽位 B（正在更新）
        │                             │ 写入、验签
        │                             ▼
        │                      标记 B 为 trial（下次尝试启动）
        │                             │
        │          B 启动成功并达到健康条件 ─▶ B 升为 good
        │          B 连续失败 ─▶ 自动回到 A
```

更新包必须签名验证；内容/配置类更新与代码更新分开校验和分阶段发布，并支持灰度。这是 CrowdStrike 事件中“一个数据文件触发驱动崩溃”教训的直接对应 \[S8\]。

### 9.6 Watchdog

| 类型 | 机制 | 动作 |
| --- | --- | --- |
| 软锁死 | 每 CPU 定时器心跳未更新 | 记录并告警，超限升级 |
| 硬锁死 | NMI 检测关中断下的长时间无进展 | 输出现场，进入 L4 |
| 驱动超时 | 驱动自身的健康与请求超时 | 重置→隔离（L2→L3） |
| 硬件看门狗 | 平台提供时才启用 | 到期自动复位 |

### 9.7 Crash Dump

```rust
// crates/aurora-diag/src/crash.rs
#[repr(C)]
pub struct CrashRecord {
    pub magic: u64,            // 用于下次启动识别有效记录
    pub version: u32,
    pub cpu: u32,
    pub fault_level: u8,
    pub vector: u8,
    pub error_code: u64,
    pub rip: u64, pub rsp: u64, pub cr2: u64, pub cr3: u64,
    pub thread_id: u64, pub process_id: u64,
    pub module_id: u16,
    pub backtrace_len: u16,
    pub backtrace: [u64; 32],
    pub log_tail_len: u32,     // 后接最近日志
}
```

记录先写入重启后保留的内存区域并同时从串口输出，下次启动在存储就绪后持久化；字段覆盖 V1.0 列出的所有项（错误类型、CPU、线程、进程、RIP、RSP、CR2、错误码、调用栈、模块、最近日志）。预留内存在各平台上是否真的跨重启保留需要实机验证，不可假设。

### 9.8 故障注入点

```rust
// crates/aurora-diag/src/inject.rs
#[macro_export]
macro_rules! fault_point {
    ($name:literal, $err:expr) => {{
        #[cfg(feature = "fault-injection")]
        { if $crate::inject::should_fail($name) { return Err($err); } }
    }};
}

// 使用示例
fn alloc(&self, order: u8, owner: ModuleId) -> Result<OwnedFrames, MmError> {
    aurora_diag::fault_point!("pmm.alloc", MmError::OutOfMemory);
    /* 正常路径 */
    # todo!()
}
```

故障注入只在测试构建中启用，由测试脚本按名称、概率或第 N 次触发，覆盖 OOM、设备超时、DMA 错误、初始化失败等场景（12）。

## 10 内核接口：系统调用、capability 与 FFI

### 10.1 系统调用入口

使用 SYSCALL/SYSRET，通过 MSR（LSTAR、STAR、SFMASK）配置，入口汇编只做切栈和保存现场，其余进入 Rust：

```rust
core::arch::global_asm!(r#"
.global syscall_entry
syscall_entry:
    swapgs                          // 切到内核 GS（指向 PerCpu）
    mov gs:[{USER_RSP}], rsp        // 保存用户栈指针（不信任它的值）
    mov rsp, gs:[{KERNEL_RSP}]      // 切到当前线程的内核栈
    // 构建 SyscallFrame：rax(编号)、rdi/rsi/rdx/r10/r8/r9(参数)、rcx(用户 RIP)、r11(用户 RFLAGS)、用户 RSP
    // ... push ...
    mov rdi, rsp
    call syscall_dispatch
    // ... pop，返回前校验用户 RIP 为规范地址 ...
    mov rsp, gs:[{USER_RSP}]
    swapgs
    sysretq
"#, USER_RSP = const PERCPU_USER_RSP, KERNEL_RSP = const PERCPU_KERNEL_RSP);
```

**入口不变量**（评审必查）：

1. 进入内核后立即切换到内核栈，不使用用户提供的 RSP。
2. `SFMASK` 在入口处清除 IF 与 DF，保证切栈前不被中断。
3. 用 `SYSRET` 返回前必须检查返回地址（RCX）是否为规范地址，非规范则改走 `IRET` 路径，避免在特权级 0 上触发异常后使用用户栈（已知的 SYSRET 类问题，细节以 Intel SDM 与 AMD APM 为准 \[R1\]）。
4. 中断与异常入口在来自用户态时必须 `swapgs`（见 5.3）。

### 10.2 ABI 约定

| 项 | 约定 |
| --- | --- |
| 调用号 | `rax` |
| 参数 | `rdi, rsi, rdx, r10, r8, r9`（最多 6 个） |
| 返回值 | `rax`：非负为成功值，负数为 `-ErrorCode` |
| 破坏寄存器 | `rcx`、`r11`（硬件行为）、`rax` |
| 版本 | `sys_abi_info()` 返回 major.minor 与特性位 |
| 兼容性 | 调用号、错误码、结构布局**只增不改**；废弃需完整周期 |

可扩展参数结构采用“首字段为 size”的模式，老程序与新内核、新程序与老内核都能工作：

```rust
#[repr(C)]
pub struct OpenArgs {
    pub size: u32,       // 调用方填写 sizeof(自己知道的版本)
    pub flags: u32,
    pub path_ptr: u64,
    pub path_len: u64,
    // 未来新增字段只能追加在末尾
}
// 内核：只拷贝 min(size, size_of::<OpenArgs>()) 字节，其余字段取默认值 0；
// 调用方传入内核不认识的非零新字段时返回 Unsupported。
```

### 10.3 用户指针与拷贝

内核不直接解引用用户指针。所有用户地址先封装为 `UserSlice`，校验后才允许拷贝：

```rust
pub const USER_MAX: u64 = 0x0000_7FFF_FFFF_F000;

pub struct UserSlice { addr: u64, len: usize }

impl UserSlice {
    pub fn new(addr: u64, len: usize) -> Result<Self, SysError> {
        let end = addr.checked_add(len as u64).ok_or(SysError::Fault)?;  // 防止溢出
        if end > USER_MAX { return Err(SysError::Fault); }
        Ok(Self { addr, len })
    }
    /// 拷贝路径在 STAC/CLAC 包裹内运行，并登记到异常修复表；
    /// 页错误时返回 Err(Fault) 而不是内核态 #PF 升级。
    pub fn copy_to_kernel(&self, dst: &mut [u8]) -> Result<(), SysError> { /* ... */ Ok(()) }
}
```

### 10.4 Capability 句柄模型（ADR-007）

进程只能通过**句柄**访问内核对象（文件、内存对象、线程、设备窗口等），每个句柄带权限位，没有“全局命名空间里的任意路径”。可参考 seL4、Fuchsia 等 capability 系统的设计 [R8](https://sel4.systems/)、[R9](https://fuchsia.dev/)（本次未核验具体页面）。

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);
impl Rights {
    pub const READ: Self = Self(1);     pub const WRITE: Self = Self(2);
    pub const MAP: Self = Self(4);      pub const DUP: Self = Self(8);
    pub const TRANSFER: Self = Self(16);
    pub fn contains(self, o: Self) -> bool { self.0 & o.0 == o.0 }
}

/// 句柄 = 槽位索引 + 代数，防止重用槽位后的旧句柄被误用。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Handle(u32);

impl HandleTable {
    pub fn get(&self, h: Handle, need: Rights) -> Result<&KernelObject, SysError> { /* 检查代数与权限 */ todo!() }
    /// 复制句柄只能缩小权限，不能扩大。
    pub fn dup(&mut self, h: Handle, new: Rights) -> Result<Handle, SysError> { /* 需要 DUP 且 new ⊆ old */ todo!() }
}
```

### 10.5 C 与 Rust 的 FFI 规范

| 规则 | 说明 |
| --- | --- |
| 数据布局 | 跨语言结构一律 `#[repr(C)]`，禁止跨边界传 Rust 枚举带数据、切片、`&str` |
| 缓冲区 | 必须指针 + 长度成对传递，入口处校验非空、长度上限 |
| 所有权 | 每个接口在注释中写明谁分配、谁释放 |
| 错误 | 统一整数错误码，不使用异常 |
| panic | 内核为 `panic = abort`，FFI 入口必须无 panic 路径（禁用 `unwrap/expect`，开启 clippy 规则） |
| 参数校验 | 所有 FFI 入口先校验再使用 |
| 白名单 | FFI 边界代码集中在 `aurora-ffi`（加入 unsafe 白名单） |

```rust
// crates/aurora-ffi/src/log.rs
#[repr(C)]
pub struct AuBuf { pub ptr: *const u8, pub len: usize }

pub const AU_OK: i32 = 0;
pub const AU_EINVAL: i32 = -22;   // 错误码表统一维护在 docs/interfaces/errors.md

#[no_mangle]
pub extern "C" fn aurora_log_write(level: u32, msg: AuBuf) -> i32 {
    let Some(level) = LogLevel::from_u32(level) else { return AU_EINVAL };
    if msg.ptr.is_null() || msg.len == 0 || msg.len > MAX_LOG_LEN { return AU_EINVAL; }
    // SAFETY: 接口契约要求 C 调用方保证 [ptr, ptr+len) 可读；非空与长度上限已在上方校验。
    let bytes = unsafe { core::slice::from_raw_parts(msg.ptr, msg.len) };
    aurora_diag::log_bytes(level, bytes);
    AU_OK
}
```

### 10.6 版本与兼容策略

| 对象 | 版本规则 |
| --- | --- |
| 内核 | 语义化版本 |
| 系统调用 ABI | major 不兼容、minor 只增不改 |
| 驱动接口（`DriverCtx`） | 独立版本号，变更需 ADR |
| 文件系统磁盘格式 | 格式版本写入超级块，支持前向检测 |
| 更新包 | 包格式版本 + 签名版本 |

## 11 安全与供应链

### 11.1 缓解措施清单（默认开启，关闭需 ADR）

| 机制 | 阶段 | 说明 |
| --- | --- | --- |
| W^X、NX | M2 | 页权限构造即强制（6.3） |
| SMEP / SMAP | M4 | 硬件支持时强制开启 |
| KASLR | M2 | 依赖 Limine 配置 \[R3\] |
| 守卫页 | M2 | 所有栈与堆区 |
| 栈保护（C 代码） | M1 | `-fstack-protector-strong` |
| CFI | 评估 | 工具链支持情况需实测后决定 |
| 顶级推测执行缓解 | M7 | 按 CPU 型号与微码能力选择，不硬编码型号 |
| IOMMU | M5 | 见 8.4 |
| 随机数 | M4 | 硬件随机源与其他熵混合，不单独依赖 RDRAND |
| 安全启动、度量启动（TPM） | M7 | 需评估 Limine 与签名链支持 \[R3\] |
| 驱动、更新包签名 | M6 | 见 9.5 |
| 审计日志 | M6 | 权限拒绝与关键操作记录 |

### 11.2 供应链规范

- `Cargo.lock` 入库；关键依赖 vendoring，禁止构建时联网拉取。
- `cargo deny`（许可证、来源、已知漏洞）[R14](https://github.com/EmbarkStudios/cargo-deny) 与 `cargo vet`（依赖审计记录）[R15](https://github.com/mozilla/cargo-vet) 纳入 CI。
- 生成 SBOM，发布产物可复现构建并签名；签名根密钥离线保存。
- 任何新增依赖需说明理由、许可证、unsafe 量；内核 TCB 内的依赖需双人评审。

### 11.3 漏洞响应

公开 `SECURITY.md`（报告渠道、响应 SLA、披露时限），设立安全负责人与应急发布流程（支持单独的安全补丁发布，不捷带功能更新）。具体 SLA 数值由安全委员会在 M9 前确定，本手册不预设。

## 12 测试与质量保障

### 12.1 七级测试体系（对 V1.0 五级的扩展）

| 级别 | 内容 | 工具 / 运行位置 |
| --- | --- | --- |
| L1 静态 | fmt、clippy、clang-tidy、依赖图、unsafe 统计 | CI 每次提交 |
| L2 宿主机单元 | 纯逻辑 crate（分配器算法、调度策略、解析器）用 `cargo test` + Miri [R10](https://github.com/rust-lang/miri) + loom [R11](https://github.com/tokio-rs/loom) | 宿主机 |
| L3 内核集成 | 模块接口、初始化顺序、资源生命周期 | QEMU 测试运行器 |
| L4 系统 | 异常、中断、多核、virtio 设备 | QEMU |
| L5 故障与压力 | 故障注入（9.8）、中断风暴、内存压力、长时间运行 | QEMU + 多种硬件配置 |
| L6 模糊 | 文件系统镜像、网络报文、ELF、系统调用参数 | cargo-fuzz [R13](https://github.com/rust-fuzz/cargo-fuzz)（宿主机解析器）；系统调用模糊可参考 syzkaller 思路 [R12](https://github.com/google/syzkaller) |
| L7 真机 | 硬件矩阵夜间回归 | 自建实验室 |

关键数据结构（伙伴分配器、句柄表、页表操作）可用 Kani [R16](https://github.com/model-checking/kani) 做有界模型检查作为补充。这些工具的适用范围与限制需在引入前实际试用验证。

### 12.2 QEMU 测试运行器

使用 QEMU 的 `isa-debug-exit` 设备把测试结果映射为进程退出码，串口输出详细过程，这是内核开发常见做法 [R4](https://os.phil-opp.com/testing/)：

```rust
#[repr(u32)]
pub enum QemuExit { Success = 0x10, Failed = 0x11 }

pub fn exit_qemu(code: QemuExit) -> ! {
    // SAFETY: 0xf4 是测试环境中 isa-debug-exit 的 I/O 端口（见 justfile 的 QEMU 参数）。
    unsafe { core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code as u32, options(nomem, nostack)); }
    loop { core::hint::spin_loop(); }
}
// QEMU 进程退出码 = (写入值 << 1) | 1：Success→33，Failed→35，CI 脚本把 33 视为通过。
```

稳定版 Rust 没有自定义测试框架，因此用“段注册”收集测试：

```rust
pub struct KTest { pub name: &'static str, pub run: fn() }

#[macro_export]
macro_rules! ktest {
    ($name:ident, $body:block) => {
        #[used] #[link_section = ".ktests"]
        static $name: $crate::KTest = $crate::KTest { name: stringify!($name), run: || $body };
    };
}
```

链接脚本（3.3）需补充：`.ktests : { __ktests_start = .; KEEP(*(.ktests)) __ktests_end = .; } :rodata`，运行器遍历两个符号之间的条目。

### 12.3 CI 门禁

| 触发 | 必须通过 |
| --- | --- |
| 每次合并请求 | L1、L2、L3、QEMU 启动测试、unsafe 统计不超预算、cargo deny |
| 每夜 | L4、L5、L6（限时）、重复启动 N 次的成功率 |
| 发布前 | L7 硬件矩阵、长时间运行、unsafe 审计报告、SBOM 与签名验证 |

不允许通过关闭测试或忽略警告绕过门禁；有例外需 ADR 记录与到期日。

### 12.4 稳定性指标

沿用 V1.0 的指标（连续启动成功率、内核异常次数、分配失败率、模块初始化失败率、资源泄漏数、锁竞争与死锁、故障恢复成功率、长时间稳定性），每项由验收负责人在里程碑开始时定义采集方法与阈值。**阈值不在本手册中预设**，避免无依据的数字。

## 13 真机必备能力（对 V1.0 的补全）

| 能力 | 要点 | 待决 |
| --- | --- | --- |
| ACPI | 设备枚举、中断路由、电源、温控；需要 AML 解释器才能完整支持 | ADR-012：自研最小实现 vs 复用现有库（需审查许可证） \[R2\] |
| 关机 / 重启 | ACPI 复位寄存器、备用方式、最后手段 | 真机验证 |
| 睡眠 / 休眠 | S3/S4 状态保存与恢复 | M7 之后 |
| 时钟 | LAPIC 定时器、TSC（需检测是否恒定）、HPET 校准 | — |
| APIC | xAPIC/x2APIC、IOAPIC、MSI/MSI-X | — |
| SMP | 通过 Limine 的多处理器请求启动 AP \[R3\]，TLB shootdown | M3b |
| 混合核心 | 性能核/能效核识别与调度提示 | M7 |
| USB | xHCI + HID（真机键鼠基本都是 USB，不能推迟到“不做”） | M7 |
| UEFI 运行时服务 | 时间、变量、复位 | 与 ADR-011 联动 |
| 桥接调试 | 真机常无串口：需 framebuffer 日志 + 持久化 crash dump + 可选网络日志 | M5 |

## 14 修订后的开发路线

调整要点：隔离与诊断提前至 M2；SMP 从 M3 拆出；用户态 + capability 提前到 M4；设备与真机独立成阶段。

| 里程碑 | 内容 | 验收 |
| --- | --- | --- |
| M0 工程基础 | 仓库、固定工具链、CI、ADR 基线、许可证决策（ADR-009） | 一条命令完成构建、镜像、QEMU 启动 |
| M1 最小启动 | 串口、日志、CPU 检测、panic 框架、QEMU 测试运行器 | 重复启动稳定，测试结果可自动判定 |
| M2 CPU、异常、内存 | GDT/IDT/TSS、PMM/VMM/堆、资源登记、故障注入框架、诊断 | 分配/释放/映射正确，预期异常可诊断 |
| M3a 单核线程与调度 | 内核线程、上下文切换、抢占调度、锁与 lockdep | 多线程稳定并发 |
| M3b SMP | APIC、AP 启动、TLB shootdown、每 CPU 队列 | 多核压力测试通过 |
| M4 用户态闭环 | syscall、capability、ELF 加载、用户指针拷贝、第一个用户进程 | 用户程序运行，非法访问被拒绝 |
| M5 设备与存储 | ACPI、PCI、IOMMU、virtio、驱动生命周期与隔离、NVMe、VFS/initramfs/FAT32 | 存储读写，驱动故障可重置或隔离 |
| M6 可靠性 | 启动循环保护、A/B 回滚、crash dump 持久化、watchdog、fuzz | 注入故障后系统可自动恢复或进入安全模式 |
| M7 真机 | USB HID、电源、硬件矩阵、安全/度量启动 | 目标硬件清单通过 |
| M8 网络与安全加固 | 网络栈、审计、漏洞响应演练 | 协议 fuzz 无高危缺陷 |
| M9 图形准备与商业化 | 显示、输入接口、安装、更新、签名、发布流程 | 可发布候选版本 |

## 15 商业化、生态与治理

### 15.1 差异化定位（ADR-013，待定）

直接做通用桌面 PC 系统，要同时面对硬件驱动和应用生态。已有 Rust 系统的公开进展也表明工作量主要在驱动、文件系统与 ABI 兼容 \[S16\]。建议在 M5 前完成定位评审，候选切入点：

| 切入点 | 硬件范围 | 生态压力 | 参考 |
| --- | --- | --- | --- |
| 虚拟机/容器客体系统 | 虚拟硬件（virtio），极小 | 需要运行标准应用 | Asterinas 面向 Kata/机密容器 \[S16\]，最新版 0.19 于 2026 年 10 月发布 [S15](https://www.opennet.ru/opennews/art.shtml?num=66460) |
| 工业/边缘 x86 设备 | 可控、可认证 | 应用少且自有 | — |
| 安全敏感专用终端 | 可控 | 强隔离与可审计是卖点 | — |
| 通用桌面 | 极大 | 最强 | 远期目标 |

### 15.2 应用生态策略

| 方案 | 说明 | 代价 |
| --- | --- | --- |
| 自有 API + Rust std 移植 | Redox 已支持 Rust 标准库并在 Rust 平台支持中为 Tier 2/3 \[S18\] | 应用少 |
| POSIX 子集 + libc 移植 | 把常见命令行工具跑起来 | 中等 |
| Linux ABI 兼容 | Asterinas 路线，已支持 210 余个系统调用 \[S14\] | 工作量大，需评估许可证与维护负担 |

**建议**：首期“自有 API + 最小 POSIX 子集”，并把 Linux ABI 兼容作为独立评估课题（等 M4 之后有真实数据再决定）。

### 15.3 驱动与硬件认证

- 公布硬件兼容清单（HCL）与“已验证/已知问题/不支持”三档状态，不方便承诺“支持所有 PC”。
- 复用其他系统的驱动代码涉及许可证（如 GPL）与接口假设，需法务与架构双评审后再决定。

### 15.4 许可证与治理（ADR-009，阻塞项）

需要在对外公开或引入外部贡献者之前确定：项目许可证（宽松型如 Redox 采用的 MIT [S20](https://lwn.net/Articles/979524)，或 copyleft）、贡献协议（CLA/DCO）、第三方代码引入规则、商标。此事涉及法律判断，请由律师确认，本手册不提供法律结论。

### 15.5 发布与支持

沿用 V1.0 的四个渠道（开发、测试、稳定、LTS）。每个渠道需定义：支持周期、安全补丁范围、回滚要求、签名密钥轮换与吃紧恢复流程。具体周期由产品和安全负责人在 M9 前确定。

### 15.6 团队与流程

- unsafe 与密码相关改动需双人评审。
- 关键模块至少两人熟悉，避免单点依赖。
- Redox 的公开报道强调贡献者招募对这类项目是生死政题 [S19](https://www.webpronews.com/redox-os-the-rust-written-operating-system-that-refuses-to-stay-niche/)，项目组织要把人才计划写进路线图。

## 附录 A 风险与模板

### A.1 风险登记册（负责人、阈值待填）

| 风险 | 影响 | 缓解 | 关联章节 |
| --- | --- | --- | --- |
| 驱动与硬件兼容不足 | 无法商用 | virtio 先行、HCL、定位收敛 | 8, 13, 15 |
| TCB 内 unsafe 缺陷 | 全系统崩溃或被攻破 | unsafe 预算、审计、Miri/Kani | 1.3, 12 |
| 工具链升级破坏构建 | 进度阻塞 | 固定版本、容器镜像 | 3 |
| 真机行为与 QEMU 不同 | 隐藏缺陷 | 真机矩阵从 M5 开始建立 | 12, 13 |
| 应用生态缺失 | 无人使用 | 明确切入点与兼容策略 | 15 |
| 许可证与法律风险 | 无法发布 | 尽早决策、律师审查 | 15.4 |
| 范围蔓延 | 延期 | 每个里程碑有写明的“不做”清单 | 14 |
| 关键人员依赖 | 项目停摆 | 文档、双人评审、招募 | 15.6 |

### A.2 ADR 模板

```text
# ADR-NNN: 标题
状态：提议 / 已采纳 / 已废弃（被 ADR-MMM 取代）
背景：要解决的问题与约束
选项：至少两个，写明优缺点
决策：选择哪个、为什么
后果：对其他模块、测试、发布的影响
回退：如果错了如何撤回
```

### A.3 模块评审清单

- 有 `DESIGN.md`（职责、接口、依赖、资源策略、错误策略、并发说明、已知限制）。
- 拆为 `-api` 与实现两个 crate，依赖图通过检查。
- 默认 `forbid(unsafe_code)`，若在白名单则每个 unsafe 有 SAFETY 注释。
- 错误类型独立、无 `unwrap/expect`、所有分配可失败。
- 锁等级已登记，中断上下文规则已遵守。
- 资源全部经资源表登记，模块故障时可撤销。
- 单元测试、集成测试、故障注入点均已提供。
- 有验收记录与性能基线。

### A.4 待决 ADR 清单

| 编号 | 主题 | 需在何时前决定 |
| --- | --- | --- |
| ADR-009 | 许可证与贡献协议 | M0 |
| ADR-011 | 启动计数与隔离名单的持久化位置 | M2 |
| ADR-012 | ACPI/AML 方案 | M5 |
| ADR-013 | 产品切入点与应用生态策略 | M5 前 |

## 附录 B 参考文献

### B.1 本次会话实际检索到的来源（\[S#\]）

编号沿用检索序号，未被引用的来源已省略。这些来源中有若干是二次报道或博客，重要结论采用前建议回溯一手来源（如论文、官方文档、厂商事故报告）。

| 编号 | 标题 | 地址 |
| --- | --- | --- |
| S1 | Rust will save Linux（Rust Week 2026 报道） | https://blog.desdelinux.net/en/Rust-Linux--Greg-Kroah-Hartman--end-of-security-experiment/ |
| S2 | Rust For Linux No Longer Experimental | https://www.i-programmer.info/news/98-languages/18527-rust-for-linux-no-longer-experimental.html |
| S3 | Rust is here to stay（Maintainers Summit 报道） | https://blog.desdelinux.net/en/linux-kernel-rust-official-android-16-drivers-drm-debate/ |
| S4 | An Empirical Study of Rust for Linux（ATC/OSDI 2024） | https://atcosdi24.sched.com/event/1fLd7/an-empirical-study-of-rust-for-linux-the-success-dissatisfaction-and-compromise |
| S6 | Microsoft, SecOps pros weigh kernel access post-CrowdStrike | https://www.techtarget.com/it-infrastructure/news/366599066/Microsoft-SecOps-pros-weigh-kernel-access-post-CrowdStrike |
| S7 | Microsoft convenes endpoint security firms（SecurityWeek） | https://www.securityweek.com/microsoft-convenes-endpoint-security-firms-following-crowdstrike-incident/amp/ |
| S8 | Lessons Learned from the CrowdStrike Global Outage | https://prog.world/lessons-learned-from-the-crowdstrike-global-outage |
| S9 | Microsoft Talks Kernel Drivers Post CrowdStrike Outage（Dark Reading） | https://www.darkreading.com/application-security/microsoft-lowballs-crowdstrike-outage-impact |
| S10 | Microsoft mulls restricting third-party access to Windows kernel | https://mspoweruser.com/microsoft-mulls-restricing-third-party-access-to-windows-kernel-after-crowdstrike-outage |
| S11 | Microsoft's Security Strategy（Business of Tech） | https://businessof.tech/2024/07/30/microsofts-security-strategy-lessons-from-crowdstrike-outage-and-potential-kernel-access-restrictions/ |
| S12 | Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS（arXiv） | https://arxiv.org/abs/2506.03876 |
| S13 | Asterinas: A Rust-Based Framekernel（USENIX ;login:） | https://www.usenix.org/node/309439 |
| S14 | Asterinas ATC'25 论文 | https://zhou-diyu.github.io/files/asterinas-atc25.pdf |
| S15 | Asterinas 0.19 发布报道（OpenNET） | https://www.opennet.ru/opennews/art.shtml?num=66460 |
| S16 | Asterinas 0.18 Lands | https://news.lavx.hu/article/asterinas-0-18-lands-a-rust-written-memory-safe-linux-alternative-targets-containers |
| S17 | Redox OS 项目目标 | https://doc.redox-os.org/book/our-goals.html |
| S18 | Redox OS 主页 | https://www.redox-os.org/home/ |
| S19 | Redox OS 进展报道（WebProNews） | https://www.webpronews.com/redox-os-the-rust-written-operating-system-that-refuses-to-stay-niche/ |
| S20 | Redox: An operating system in Rust（LWN） | https://lwn.net/Articles/979524 |
| S21 | Asterinas: a new Linux-compatible kernel project（LWN 转载） | https://hn.jakechampion.name/reader/https://lwn.net/SubscriberLink/1022920/ad60263cd13c8a13 |

### B.2 通用参考（\[R#\]，本次会话未核验页面内容）

这些地址是常见的官方规范或开源项目主页，按记忆给出，**采用前请打开确认内容与版本**。

| 编号 | 资料 | 地址 |
| --- | --- | --- |
| R1 | Intel 软件开发者手册（SDM）；AMD APM 需另查 AMD 官网 | https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html |
| R2 | UEFI / ACPI 规范 | https://uefi.org/acpi/specs、https://uefi.org/specifications |
| R3 | Limine 引导程序与启动协议 | https://github.com/limine-bootloader/limine |
| R4 | Writing an OS in Rust（测试篇） | https://os.phil-opp.com/testing/ |
| R5 | Rust `x86_64-unknown-none` 目标平台支持页 | https://doc.rust-lang.org/nightly/rustc/platform-support/x86\_64-unknown-none.html |
| R6 | OSDev Wiki | https://wiki.osdev.org/ |
| R7 | rust-osdev/x86\_64 | https://github.com/rust-osdev/x86\_64 |
| R8 | seL4 | https://sel4.systems/ |
| R9 | Fuchsia | https://fuchsia.dev/ |
| R10 | Miri | https://github.com/rust-lang/miri |
| R11 | loom | https://github.com/tokio-rs/loom |
| R12 | syzkaller | https://github.com/google/syzkaller |
| R13 | cargo-fuzz | https://github.com/rust-fuzz/cargo-fuzz |
| R14 | cargo-deny | https://github.com/EmbarkStudios/cargo-deny |
| R15 | cargo-vet | https://github.com/mozilla/cargo-vet |
| R16 | Kani | https://github.com/model-checking/kani |

---

**本手册的局限**：代码未编译验证；新闻类来源为二次报道；ADR 为建议而非已评审结论；所有“阈值”“SLA”“支持周期”均有意留空。在架构评审会上逐章确认后，再把所有 ADR 固化到 `docs/adr/`。
