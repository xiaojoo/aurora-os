# unsafe 现场普查（逐处审计表）

> 本文件与 `docs/security/unsafe-whitelist.toml` 同源：上面的登记表存「模块 × 类别 → 处数」，这里给出每一处**具体在哪一行、长什么样**，
> 供「类别判错了要能翻到现场」时使用。数字由 `python tools/aurora.py check`（`check-unsafe`）双向对账。
>
> **2026-11-20（ADR-175 跨 AS 读走物理地址）**：`sched/user` U2 9 → 10（`copy_from_user_in` 里 HHDM 别名的单字节读）。**总数 +1**（530 → 531）。

总计 570 处。U1 85 · U2 157 · U3 13 · U4 149 · U5 128 · U6 38

| 类别 | 含义 | 处数 |
|---|---|---|
| U1 | 架构入口与特殊寄存器 | 85 |
| U2 | 页表、物理内存与 MMIO | 121 |
| U3 | DMA 与设备共享内存 | 13 |
| U4 | 并发共享状态与 UnsafeCell | 149 |
| U5 | 用户指针与地址空间访问 | 128 |
| U6 | 诊断路径的有限现场读取 | 36 |

### capability/handle

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 315 | `unsafe {` （`SlotArray::allocate` 的清零循环：`core::ptr::write(p.add(i), EMPTY)`） |
| U2 | 326 | `unsafe {` （清零后的校验循环：`core::ptr::read(p.add(i)).used`） |
| U2 | 353 | `unsafe { core::slice::from_raw_parts(base as *const Entry, len) }` |
| U2 | 362 | `unsafe { core::slice::from_raw_parts_mut(base as *mut Entry, len) }` |

ADR-179：句柄槽数组从 `.bss` 改为运行时分配。四处的指针来源都是 `phys_alloc_above`
分出的 MOD_BOOT 连续帧（永不归还）、长度 `MAX_HANDLES`、生命周期整个内核，
访问都在 `RANK_HANDLE(35)` 锁内。
### arch/hooks

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 42 | `unsafe impl Sync for HooksCell {}  fn no_mark_tick() {}` |
| U4 | 83 | `unsafe { *HOOKS.0.get() = h; } } ` |
| U4 | 88 | `unsafe { &*HOOKS.0.get() } }` |

### arch/x86_64/apic

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 280 | `unsafe { *STATE_COPY.0.get() } } else { None` |
| U4 | 288 | `unsafe impl Sync for StateCell {} static STATE_COPY: StateCell = StateCell(core::cell::UnsafeCell::new(None));` |
| U2 | 295 | `unsafe { core::ptr::read_volatile((base + off) as *const u32) } } ` |
| U2 | 301 | `unsafe { core::ptr::write_volatile((base + off) as *mut u32, v) }; } ` |
| U4 | 401 | `unsafe { *STATE_COPY.0.get() = Some(s) }; STATE.store(1, Ordering::Release); Ok(s)` |
| U1 | 685 | `unsafe { core::arch::asm!("sti", options(nomem, nostack)) }; } ` |
| U1 | 691 | `unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; if slot < crate::arch::x86_64::cpu::MAX_CPUS { CP` |
| U1 | 717 | `unsafe { core::arch::asm!("sti", options(nomem, nostack)) }; } let r = f();` |
| U1 | 722 | `unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; CPU_IF[slot].store(false, Ordering::Release); }` |

### arch/x86_64/cpu

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 51 | `unsafe { core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, preserves_flags)); // 只加要加的位，绝不整份覆盖：boot` |
| U1 | 66 | `unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, preserves_flags)) }; v }` |
| U1 | 91 | `unsafe { core::arch::asm!("rdmsr", in("ecx") msr, lateout("eax") lo, lateout("edx") hi, options(nomem, preserv` |
| U1 | 101 | `unsafe { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nome` |
| U1 | 114 | `unsafe { let mut v: u64; core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, preserves_flags));` |

### arch/x86_64/smp

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 47 | `unsafe impl Sync for ApBootCell {} static AP_ARGS: [ApBootCell; cpu::MAX_CPUS] = [const { ApBootCell(UnsafeCel` |
| U4 | 53 | `let a = unsafe { &*AP_ARGS[slot].0.get() }; (a.stack_top, a.slot, a.expect_lapic) }` |
| U1 | 198 | `unsafe { ap_entry_gate[0] } } ` |
| U4 | 278 | `unsafe { *AP_ARGS[slot].0.get() = ApBoot { stack_top: top, slot: slot as u64, expect_lapic: lapic_id as u64 };` |
| U4 | 284 | `unsafe { limine::release_mp_cpu(mp.cpu_ptrs[i] as *mut limine::MpInfo, AP_ARGS[slot].0.get() as u64, ap_entry_` |
| U1 | 469 | `unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }; } // 10) 停机：先关窗口（立牌 + `cli`）再关定时器，之后不再碰任何共享状态。` |
| U1 | 477 | `unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; AP_STAGE[slot].store(3, Ordering::Release); halt_` |
| U1 | 485 | `unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) }; } }` |
| U1 | 530 | `unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }; } }` |
| U4 | 556 | `unsafe impl Sync for RaceCell {} static RACE: RaceCell = RaceCell(UnsafeCell::new(0)); ` |
| U4 | 632 | `unsafe { let p = RACE.0.get(); let v = core::ptr::read_volatile(p);` |
| U4 | 725 | `unsafe impl Sync for RoleCell {} static AP_ROLE: RoleCell = RoleCell(core::cell::UnsafeCell::new(None)); ` |
| U4 | 737 | `unsafe { *AP_ROLE.0.get() = Some(role) }; for &s in &aps[..n] { ENTERED[s].store(0, Ordering::Relaxed);` |
| U4 | 759 | `unsafe { *AP_ROLE.0.get() = None }; if !ack_ok { return Err(ack_fail(PHASE_WAIT_WAKE, RaceError::AckTimeout));` |
| U4 | 769 | `let role = unsafe { *AP_ROLE.0.get() }; if let Some(f) = role { f();` |
| U4 | 849 | `unsafe { core::ptr::write_volatile(RACE.0.get(), 0) }; PHASE.store(phase, Ordering::Release); // 1) 等所有 AP 声称"` |
| U4 | 867 | `let observed = unsafe { core::ptr::read_volatile(RACE.0.get()) }; let expected = (aps.len() as u64 + 1) * RACE` |

### arch/x86_64/trap

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 126 | `unsafe { let base = core::ptr::addr_of_mut!((*TABLES[slot].0.get()).tss) as *const u8; Some((` |
| U4 | 221 | `unsafe impl Sync for TablesSlot {}  static TABLES: [TablesSlot; crate::arch::x86_64::cpu::MAX_CPUS] = [const {` |
| U1 | 297 | `let t = unsafe { &mut *TABLES[slot].0.get() };  t.gdt[0] = 0;` |
| U1 | 327 | `unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), ist1) };  let has_err = vectors_wit` |
| U1 | 339 | `unsafe { isr_shootdown_gate[0] } } else { unsafe { isr_table[v] }` |
| U1 | 341 | `unsafe { isr_table[v] } }; t.idt[v] = idt_gate(` |
| U1 | 360 | `unsafe { core::arch::asm!("lgdt [{}]", in(reg) &gdtr); flush_segments(SEL_CODE, SEL_DATA);` |
| U1 | 395 | `let t = unsafe { &mut *TABLES[slot].0.get() }; // SAFETY: packed 字段，见 `Tss` 注释；偏移由 `tss_offsets` 复核 unsafe { c` |
| U1 | 397 | `unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), top) }; Ok(ExStackInfo { guard_va, ` |
| U4 | 602 | `unsafe impl Sync for StatsTable {} static STATS: StatsTable = StatsTable(core::cell::UnsafeCell::new([const { ` |
| U4 | 615 | `unsafe { &(*STATS.0.get())[slot] } } ` |
| U4 | 1052 | `let t = unsafe { &mut *TABLES[slot].0.get() }; // SAFETY: packed 字段必须按不可对齐的方式写（见 `Tss` 的注释：这个字段落在 // 偏移 4，而 `u` |
| U1 | 1055 | `unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.rsp0), va) }; // 同一个值发布给快路径：`SYSCALL` 不查 TSS` |
| U4 | 1061 | `unsafe { (*FAST_AREAS[slot].0.get()).kstack_top = va; }` |
| U1 | 1087 | `Some(unsafe { (*TABLES[slot].0.get()).gdt[i] }) } ` |
| U1 | 1103 | `pub unsafe extern "C" fn aurora_trap_entry(frame: &mut TrapFrame) { // P3/P5 的下界读数（新边界见 `isr_common` 出口那段的注释：不` |
| U1 | 1149 | `unsafe { core::arch::asm!("call pf_probe", in("rdi") addr, lateout("rax") ret, options(preserves_flags)); }` |
| U1 | 1181 | `unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) }; } }` |
| U4 | 1225 | `unsafe impl Sync for FastSlotCell {} static FAST_AREAS: [FastSlotCell; crate::arch::x86_64::cpu::MAX_CPUS] = [` |
| U4 | 1252 | `let a = unsafe { &*FAST_AREAS[slot].0.get() }; Some((a.kstack_top, a.slot)) }` |
| U4 | 1291 | `unsafe { (*FAST_AREAS[slot].0.get()).slot = slot as u64; }` |
| U1 | 1722 | `seen[i] = unsafe { isr_table[i] }; } let mut n = 0;` |

### boot/limine

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 159 | `unsafe fn response<T>(p: &AtomicPtr<T>) -> Option<&T> { // SAFETY: 由本函数的调用约定保证（见函数文档） unsafe { p.load(Ordering` |
| U2 | 161 | `unsafe { p.load(Ordering::Relaxed).cast_const().as_ref() } } ` |
| U2 | 182 | `unsafe { response(&self.response) } } }` |
| U2 | 283 | `unsafe { response(&self.response) } } }` |
| U3 | 329 | `pub unsafe fn release_mp_cpu(p: *mut MpInfo, extra_argument: u64, entry: u64) { // SAFETY: 见函数文档。extra_argumen` |
| U3 | 332 | `unsafe { core::ptr::write_volatile(&raw mut (*p).extra_argument, extra_argument) }; // goto_address 是 AtomicU6` |
| U3 | 335 | `unsafe { &*(&raw const (*p).goto_address as *const core::sync::atomic::AtomicU64) } .store(entry, Ordering::Re` |
| U2 | 358 | `let info = unsafe { resp.cpus.add(i).read() }; if info.is_null() { m.all_goto_null = false;` |
| U3 | 364 | `let info = unsafe { &*info }; if info.goto_address.load(Ordering::Acquire) != 0 { m.all_goto_null = false;` |
| U2 | 402 | `unsafe fn memmap_slice(resp: &MemmapResponse) -> &[*const MemmapEntry] { let base = resp.entries.load(Ordering` |
| U2 | 405 | `unsafe { core::slice::from_raw_parts(base, resp.entry_count as usize) } } ` |
| U2 | 430 | `let byte = unsafe { p.add(n).read_volatile() }; if byte == 0 \|\| !(0x20..0x7f).contains(&byte) { break;` |
| U2 | 440 | `core::str::from_utf8(unsafe { core::slice::from_raw_parts(p, n) }).ok() } });` |
| U2 | 444 | `let mmap_entries = unsafe { memmap_slice(memmap) }; Some(BootInfo { hhdm_offset: hhdm.offset, mmap_entries, rs` |
| U2 | 484 | `let fb: *const Framebuffer = unsafe { *base }; if fb.is_null() { return None;` |
| U2 | 489 | `let f = unsafe { &*fb }; Some(FbInfo { count: r.framebuffer_count,` |
| U2 | 520 | `let entries = unsafe { memmap_slice(m) }; for e in entries { // SAFETY: 条目指针由 bootloader 提供；collect() 已经在按同样方式` |
| U2 | 523 | `let Some(e) = (unsafe { e.as_ref() }) else { continue }; if MemmapType::from_raw(e.kind) == MemmapType::Frameb` |

### bus/acpi

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 188 | `unsafe impl Sync for SumCellSync {} static SUM_CELL: SumCellSync = SumCellSync(UnsafeCell::new(SumCell { inner` |
| U4 | 194 | `unsafe { (*SUM_CELL.0.get()).inner = Some(s) }; SUMMARY.store(1, Ordering::Release); }` |
| U4 | 203 | `unsafe { (*SUM_CELL.0.get()).inner } } ` |
| U2 | 255 | `*o = unsafe { core::ptr::read_volatile((va as usize + i) as *const u8) }; } Ok(())` |
| U4 | 427 | `unsafe { (*REFS.0.get())[i] = refs[i] }; } for r in refs.iter().flatten() {` |
| U4 | 621 | `unsafe impl Sync for RefsCell {} static REFS: RefsCell = RefsCell(UnsafeCell::new([None; MAX_TABLES])); ` |
| U4 | 630 | `unsafe { (*REFS.0.get())[i] } } ` |

### bus/hw

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 58 | `Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u8) }) } ` |
| U2 | 63 | `Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u16) }) } ` |
| U2 | 68 | `Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u32) }) } ` |
| U2 | 74 | `unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u16, v) }; Ok(()) }` |
| U2 | 81 | `unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u8, v) }; Ok(()) }` |
| U2 | 88 | `unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u32, v) }; Ok(()) }` |
| U2 | 103 | `unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (self.base() + off as u64) as *mut u32, src.len()); }` |
| U1 | 116 | `unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags))` |
| U1 | 124 | `unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags))` |

### bus/pci

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 51 | `unsafe impl Sync for TableCell {} static TABLE: TableCell = TableCell(UnsafeCell::new(None)); ` |
| U4 | 58 | `unsafe impl Sync for EcamCell {} static ECAM: EcamCell = EcamCell(UnsafeCell::new(None)); ` |
| U4 | 66 | `unsafe { (*ECAM.0.get()).as_ref().map(\|r\| r.base()) } } ` |
| U2 | 78 | `unsafe { core::ptr::read_volatile((va + o) as *const u32) } } None => {` |
| U2 | 97 | `unsafe { core::ptr::write_volatile((va + o) as *mut u32, v) } } None => {` |
| U4 | 108 | `unsafe { (*TABLE.0.get()).as_ref().map(\|(i, _)\| *i) } } ` |
| U4 | 113 | `unsafe { (*TABLE.0.get()) .as_ref()` |
| U4 | 168 | `unsafe { *ECAM.0.get() = Some(r) }; backend = Backend::Ecam; crate::log_info!("pci: ECAM pa={:#x} va={:#x} spa` |
| U4 | 203 | `unsafe { *TABLE.0.get() = Some((info, out)) }; info }` |
| U2 | 214 | `unsafe { core::ptr::read_volatile((va + o) as *const u32) } } None => 0,` |

### diag/crash

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 270 | `let next = unsafe { (fp as *const u64).read_volatile() }; // SAFETY: 同上，偏移在同一个已映射的帧内（rbp 指向帧头，+8 不会越出这一页的 //  ` |
| U6 | 273 | `let ret = unsafe { ((fp + 8) as *const u64).read_volatile() }; // 先记这一帧，再决定要不要往上走：这一层帧的返回地址是有效的，即使它的上一帧 // 的链断` |

### diag/serial

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 23 | `unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) }` |
| U1 | 30 | `unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) }` |

### display/frame

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 122 | `unsafe { ROW_DIRTY.iter_mut().for_each(\|d\| *d = true) }; true }` |
| U2 | 134 | `unsafe { if ROW_DIRTY[y] { let row = &BACK[y * w..(y + 1) * w];` |
| U2 | 218 | `unsafe { BACK[self.back_idx(x, y)] = self.pack(rgb); ROW_DIRTY[y as usize] = true;` |
| U2 | 236 | `unsafe { BACK[self.back_idx(x, y)] = packed; ROW_DIRTY[y as usize] = true;` |
| U2 | 295 | `return Ok(unsafe { BACK[self.back_idx(x, y)] }); } self.region.read32(off).map_err(FrameError::Map)` |

### driver/ahci

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 307 | `unsafe impl Sync for RingCell {} static RING: RingCell = RingCell(UnsafeCell::new(None)); ` |
| U4 | 464 | `unsafe { (*RING.0.get()).as_ref().map(\|r\| r.info) } } ` |
| U4 | 471 | `unsafe { (*RING.0.get()).as_ref().map(\|r\| (r.ctx, r.mmio)).ok_or(AhciError::NotClaimed) } } ` |
| U4 | 477 | `unsafe { (*RING.0.get()).as_ref().map(\|r\| (r.ctx, r.dma)).ok_or(AhciError::NotClaimed) } } ` |
| U4 | 666 | `unsafe impl Sync for ArmCell {} static ARM: ArmCell = ArmCell(UnsafeCell::new(None)); ` |
| U4 | 726 | `unsafe { *ARM.0.get() = Some(h) }; Ok(h.vector) }` |
| U4 | 790 | `unsafe { *ARM.0.get() } } ` |
| U4 | 807 | `unsafe { *ARM.0.get() = None }; } ` |
| U4 | 1102 | `unsafe { *RING.0.get() = Some(Ring { ctx, mmio, dma, info }) }; fill(0, 0xEE, RING_PAGES * mm::PAGE)?; Ok(info` |

### driver/mod

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 137 | `unsafe impl Sync for TableCell {} static TABLE: TableCell = TableCell(UnsafeCell::new(Table::empty())); ` |
| U4 | 204 | `let t = unsafe { &mut *TABLE.0.get() }; let slot = t.free_mmio_slot().ok_or(DriverError::ResourceExhausted)?; ` |
| U4 | 217 | `let e = unsafe { &*TABLE.0.get() }.mmio[i].as_ref().ok_or(DriverError::NoSuchHandle(h.slot))?; check_m(e, h.sl` |
| U4 | 266 | `match unsafe { &mut *TABLE.0.get() }.mmio[i].take() { Some(_) => Ok(()), None => Err(DriverError::NoSuchHandle` |
| U4 | 307 | `let t = unsafe { &mut *TABLE.0.get() }; let slot = t.free_dma_slot().ok_or(DriverError::ResourceExhausted)?; l` |
| U4 | 320 | `let e = unsafe { &*TABLE.0.get() }.dma[i].as_ref().ok_or(DriverError::NoSuchHandle(h.slot))?; check_d(e, h.slo` |
| U3 | 348 | `Ok(unsafe { core::ptr::read_volatile(at as *const u8) }) } ` |
| U3 | 357 | `Ok(unsafe { core::ptr::read_volatile(at as *const u32) }) } ` |
| U3 | 368 | `Ok(unsafe { core::ptr::read_volatile(at as *const u16) }) } ` |
| U3 | 374 | `Ok(unsafe { core::ptr::write_volatile(at as *mut u8, v) }) } ` |
| U3 | 384 | `Ok(unsafe { core::ptr::write_volatile(at as *mut u16, v) }) } ` |
| U3 | 393 | `Ok(unsafe { core::ptr::write_volatile(at as *mut u32, v) }) } ` |
| U3 | 407 | `unsafe { core::ptr::write_volatile(at as *mut u8, *b) }; } Ok(())` |
| U3 | 415 | `Ok(unsafe { core::ptr::write_bytes(at as *mut u8, pat, n) }) } ` |
| U3 | 424 | `*o = unsafe { core::ptr::read_volatile((at + i as u64) as *const u8) }; } Ok(())` |
| U4 | 437 | `match unsafe { &mut *TABLE.0.get() }.dma[i].take() { Some(_) => Ok(()), None => Err(DriverError::NoSuchHandle(` |
| U4 | 502 | `let t = unsafe { &*TABLE.0.get() }; (t.mmio.iter().filter(\|e\| e.is_some()).count(), t.dma.iter().filter(\|e\` |
| U4 | 534 | `unsafe { &*TABLE.0.get() }.mmio[usize::from(slot)].as_ref().map(\|e\| e.gen) } ` |

### driver/nvme

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 199 | `unsafe impl Sync for Cell {}  /// 一个队列的提交/完成游标。` |
| U4 | 252 | `unsafe { (*STATE.0.get()).as_ref().map(\|s\| s.reading) } } ` |
| U4 | 258 | `unsafe { (*STATE.0.get()).as_ref().map(\|s\| s.nsze) } } ` |
| U4 | 264 | `unsafe { (*STATE.0.get()).as_ref().map(\|s\| s.lba_bytes) } } ` |
| U4 | 288 | `if unsafe { (*STATE.0.get()).is_some() } { // 幂等：已经初始化过就直接回读数 return Ok(reading().unwrap_or_else(\|\| unreacha` |
| U4 | 492 | `unsafe { *STATE.0.get() = Some(st) }; Ok(out) }` |
| U4 | 696 | `let st = unsafe { (*STATE.0.get()).as_mut() }.ok_or(NvmeError::NoDevice)?; let n = buf.len().min(st.lba_bytes)` |

### driver/virtio

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 459 | `unsafe impl Sync for DevCell {}  impl DevCell {` |
| U4 | 476 | `unsafe { (*slot.0.get()).as_ref().map(f).ok_or(VirtioError::NoDevice)? } } ` |
| U4 | 633 | `unsafe { *DEVS[slot].0.get() = Some(bound) }; Ok(()) }` |
| U4 | 928 | `unsafe impl Sync for NetCell {} static NET_DEV: NetCell = NetCell(core::cell::UnsafeCell::new(None)); static N` |
| U4 | 934 | `unsafe { (*NET_DEV.0.get()).as_ref().map(f).ok_or(VirtioError::NoDevice)? } } ` |
| U4 | 940 | `if unsafe { (*NET_DEV.0.get()).is_some() } { return Ok(()); }` |
| U4 | 1039 | `unsafe { *NET_DEV.0.get() = Some(net) }; Ok(()) }` |
| U4 | 1045 | `unsafe { (*NET_DEV.0.get()).as_ref().map(\|d\| NetInfo { bdf: d.bdf,` |

### filesystem/fs_open

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 29 | `let p = unsafe { core::ptr::addr_of!(ROOT_PORT).read_volatile() }; if p == 0 { PORT } else { p } }` |
| U2 | 36 | `unsafe { core::ptr::addr_of_mut!(ROOT_PORT).write_volatile(p) } } pub const OPEN_READ_ONLY: u64 = 0;` |

### irq/mod

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 109 | `unsafe impl Sync for TableCell {} static TABLE: TableCell = TableCell(UnsafeCell::new(Table::empty())); /// 落进` |
| U4 | 138 | `let t = unsafe { &mut *TABLE.0.get() }; let Some(slot) = t.slots.iter().position(\|e\| e.is_none()) else { ret` |
| U4 | 163 | `let t = unsafe { &mut *TABLE.0.get() }; let i = h.slot as usize; if i >= SLOTS {` |
| U4 | 189 | `let t = unsafe { &*TABLE.0.get() }; t.slots[usize::from(vector) - VEC_FIRST].as_ref().map_or(st.id as u8, \|e\` |
| U4 | 212 | `let t = unsafe { &mut *TABLE.0.get() }; let e = t.slots[usize::from(vector) - VEC_FIRST] .as_mut()` |
| U4 | 225 | `let t = unsafe { &*TABLE.0.get() }; t.slots[usize::from(vector) - VEC_FIRST] .as_ref()` |
| U4 | 241 | `let t = unsafe { &*TABLE.0.get() }; let e = t.slots[usize::from(vector) - VEC_FIRST].as_ref(); Ok((` |
| U4 | 254 | `let t = unsafe { &*TABLE.0.get() }; let i = h.slot as usize; if i >= SLOTS {` |
| U4 | 288 | `let ran = unsafe { let t = &*TABLE.0.get(); match t.slots[vector - VEC_FIRST].as_ref() {` |

### ktests/boot/acpi

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 33 | `let got = unsafe { core::ptr::read_volatile((raw as *const u8).add(i)) }; if got != SIG[i] { crate::log_fatal!` |

### ktests/diag/crash

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 249 | `let v = unsafe { (BAD as *const u64).read_volatile() }; crate::log_fatal!("oops: 没有发生故障，读到 {:#x} ⇒ 这条构建没在量它声称的` |

### ktests/memory/heap

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 43 | `unsafe { core::ptr::write_bytes(p, 0x5a, 100) }; // SAFETY: 同一槽位归还 unsafe {` |
| U6 | 45 | `unsafe { if !heap::dealloc_small(p, 100) { return false;` |
| U6 | 102 | `unsafe { core::ptr::write_volatile(p, 0x4c); core::ptr::write_volatile(p.add(cls - 1), 0x7a);` |
| U6 | 107 | `let head_ok = unsafe { core::ptr::read_volatile(p) } == 0x4c; let tail_ok = unsafe { core::ptr::read_volatile(` |
| U6 | 108 | `let tail_ok = unsafe { core::ptr::read_volatile(p.add(cls - 1)) } == 0x7a; if !(head_ok && tail_ok) { crate::l` |
| U6 | 122 | `unsafe { if !heap::dealloc_small(p, cls) { return false;` |

### ktests/memory/mm

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 27 | `let v = unsafe { core::ptr::read_volatile(p as *const u8) }; v == 0xa5 };` |
| U6 | 220 | `unsafe { core::ptr::write_volatile(m.virt().0 as *mut u64, MAGIC) }; // SAFETY: 同上 let got = unsafe { core::pt` |
| U6 | 222 | `let got = unsafe { core::ptr::read_volatile(m.virt().0 as *mut u64) }; let mapped_before = mm::is_mapped(m.vir` |
| U6 | 372 | `unsafe { core::ptr::write_volatile((va0.0 + k * mm::PAGE as u64) as *mut u64, MAGIC ^ k) }; } if cfg!(feature ` |
| U6 | 381 | `let canary = unsafe { core::ptr::read_volatile(va0.0 as *const u64) }; let intact = err == Some(mm::MmError::O` |
| U6 | 423 | `let got = unsafe { core::ptr::read_volatile(va as *const u64) }; canary &= got == MAGIC ^ k; let eff = mm::eff` |
| U6 | 477 | `let cross = unsafe { core::ptr::write_volatile(m.virt().0 as *mut u64, MAGIC ^ 0xAA); let r1 = core::ptr::read` |
| U6 | 601 | `let w_cross = unsafe { mm::aspace_switch(pml4, me, Some(h.slot())) }; let mut same_writes = 0usize; for _ in 0` |
| U6 | 604 | `if unsafe { mm::aspace_switch(pml4, me, Some(h.slot())) } { same_writes += 1; }` |
| U6 | 610 | `let w_back = unsafe { mm::aspace_switch_kernel(me) }; let c1 = mm::counters(); let a2 = w_cross && same_writes` |
| U6 | 690 | `let _ = unsafe { mm::aspace_switch(pml4, me, Some(h.slot())) }; let _ = unsafe { mm::aspace_switch_kernel(me) ` |
| U6 | 691 | `let _ = unsafe { mm::aspace_switch_kernel(me) }; let bm_after_switch = mm::aspace_running_on(0).unwrap_or(0); ` |
| U2 | 975 | `unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), f.base().via_hhdm().0 as *mut u8, bytes.len()); }` |
| U6 | 1148 | `unsafe { core::ptr::copy_nonoverlapping(blob2.as_ptr(), (code2_frame + mm::hhdm()) as *mut u8, blob2.len()); }` |
| U2 | 2049 | `unsafe { core::ptr::read_volatile((fr as usize + 10 * 8) as *const u64) } } None => u64::MAX,` |
| U2 | 2658 | `let v = unsafe { core::ptr::read_volatile(AS_VA as *const u64) }; ASR[idx].store(v, Ordering::Release); crate:` |
| U6 | 2767 | `let _ = unsafe { mm::aspace_switch_kernel(me) }; let lock_in = crate::sync::stats().acquires; // SAFETY: pml4_` |
| U6 | 2770 | `wrote_a2 = unsafe { mm::aspace_switch(pml4_a2, me, Some(a2.slot())) }; let d = crate::sync::stats().acquires.w` |
| U6 | 2773 | `back_kernel = unsafe { mm::aspace_switch_kernel(me) }; lock_delta = d; if d == 0 {` |
| U6 | 2788 | `let _ = unsafe { mm::aspace_switch_kernel(me) }; // SAFETY: 同一个内核根再切一次；返回 false 才说明 CR3 确实已经在内核表上 let back = !` |
| U6 | 2790 | `let back = !unsafe { mm::aspace_switch(mm::our_cr3(), me, None) }; // 任务先死、映射再丢、AS 最后销毁（ADR-074 的契约顺序） let _ =` |

### ktests/sched/sched

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 1571 | `unsafe { core::ptr::addr_of!((*f.as_ptr()).rflags) as u64 - base } }; let size_ok = core::mem::size_of::<trap:` |
| U1 | 1581 | `unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) }; let opened = words[20]; // SAFETY: 同上` |
| U1 | 1584 | `unsafe { sched::if_patch(words.as_mut_ptr() as u64, 0) }; let closed = words[20]; // 另外还要确认"置位"这条分支幂等，且不会顺手清掉别` |
| U1 | 1589 | `unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) }; let idempotent = words[20]; let untouched = words` |
| U6 | 1766 | `unsafe { core::ptr::write_volatile(win.0 as *mut u64, 0x5a5a_5a5a_5a5a_5a5a) }; let written = unsafe { core::p` |
| U6 | 1767 | `let written = unsafe { core::ptr::read_volatile(win.0 as *const u64) }; drop(m); let after = mm::shootdown_sta` |

### ktests/security/sign

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 108 | `unsafe impl Sync for PkgScratch {} #[cfg(feature = "sig-check")] static PKG_BUF: PkgScratch = PkgScratch(Unsaf` |
| U4 | 134 | `let buf = unsafe { &mut *PKG_BUF.0.get() }; let mut off = 0usize; let mut reads = 0usize;` |

### ktests/storage/fs

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 556 | `unsafe impl Sync for ElfDiskScratch {} #[cfg(feature = "fat32-exec")] static ELF_DISK: ElfDiskScratch = ElfDis` |
| U6 | 650 | `unsafe { let buf = &mut *dst; buf[fed..fed + chunk.len()].copy_from_slice(chunk);` |
| U6 | 660 | `let head = unsafe { (*dst).as_ptr() }; (w, unsafe { core::slice::from_raw_parts(head, size) }) }` |
| U6 | 661 | `(w, unsafe { core::slice::from_raw_parts(head, size) }) } Err(e) => {` |

### ktests/syscall/elf

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 21 | `unsafe impl Sync for ElfScratch {} static ELF_BUF: ElfScratch = ElfScratch(UnsafeCell::new([0u8; ELF_SCRATCH])` |
| U4 | 34 | `let buf = unsafe { &mut *ELF_BUF.0.get() }; buf[..n].copy_from_slice(HELLO_ELF); Some(f(&mut buf[..n]))` |

### ktests/syscall/user

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 146 | `let w = unsafe { [ core::ptr::read_volatile(f as *const u64),` |

### main

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 137 | `unsafe impl Sync for MpCell {} static MP_SNAP: MpCell = MpCell(UnsafeCell::new(MpSlot(None))); ` |
| U4 | 143 | `unsafe { (*MP_SNAP.0.get()) = MpSlot(Some(m)) }; } ` |
| U4 | 148 | `unsafe { (*MP_SNAP.0.get()).0 } } ` |
| U4 | 718 | `unsafe impl Sync for BootPkgCell {} static BOOT_PKG_BUF: BootPkgCell = BootPkgCell(UnsafeCell::new([0u8; sign:` |
| U4 | 761 | `let buf = unsafe { &mut *BOOT_PKG_BUF.0.get() }; let mut off = 0usize; let mut reads = 0usize;` |

### memory/heap

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 281 | `st.free[ci] = unsafe { *(p as *const usize) }; st.live_slots[ci] += 1; drop(g);` |
| U2 | 315 | `pub unsafe fn dealloc_small(ptr: *mut u8, size: usize) -> bool { let Some(ci) = class_of(size) else { return f` |
| U2 | 328 | `unsafe { *(ptr as *mut usize) = st.free[ci] }; st.free[ci] = p; st.live_slots[ci] = st.live_slots[ci].saturati` |
| U2 | 374 | `unsafe impl GlobalAlloc for AuroraGlobal { unsafe fn alloc(&self, layout: Layout) -> *mut u8 { // 返回空指针 = 走 ha` |
| U2 | 375 | `unsafe fn alloc(&self, layout: Layout) -> *mut u8 { // 返回空指针 = 走 handle_alloc_error = L4。这是稳定版接口给的唯一选项， // 不是我` |
| U2 | 381 | `unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { if ptr.is_null() { return;` |
| U2 | 386 | `if !unsafe { dealloc_small(ptr, layout.size()) } { crate::log_fatal!("L4: dealloc 参数无法归入任何大小类 size={} ptr={:p}` |

### memory/mm

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 324 | `unsafe impl Sync for StateCell {}  static S: StateCell = StateCell(UnsafeCell::new(State {` |
| U4 | 355 | `unsafe impl Sync for RegionsCell {}  static REGIONS: RegionsCell = RegionsCell(UnsafeCell::new(` |
| U4 | 364 | `unsafe { &mut *REGIONS.0.get() } } ` |
| U4 | 373 | `unsafe { &mut *S.0.get() } } ` |
| U2 | 817 | `let e = unsafe { &*p }; if n >= MAX_REGIONS { return Err(MmError::Unsupported);` |
| U2 | 854 | `let img_lo = (unsafe { &raw const __text_start } as u64) & !(PAGE as u64 - 1); let split = align_up(unsafe { &` |
| U2 | 855 | `let split = align_up(unsafe { &raw const __rodata_end } as u64, PAGE as u64); let data_lo = (unsafe { &raw con` |
| U2 | 856 | `let data_lo = (unsafe { &raw const __data_start } as u64) & !(PAGE as u64 - 1); let img_hi = align_up(unsafe {` |
| U2 | 857 | `let img_hi = align_up(unsafe { &raw const __bss_end } as u64, PAGE as u64); let image_phys = exec_region_phys_` |
| U1 | 894 | `unsafe { core::arch::asm!( "call mm_relocate",` |
| U2 | 1015 | `unsafe { core::ptr::write_bytes((phys + st.hhdm) as *mut u8, 0, PAGE) }; Some(phys) }` |
| U2 | 1025 | `unsafe fn walk_leaf(va: u64, create: bool, huge: bool, user: bool) -> Option<*mut u64> { // SAFETY: 同 walk_lea` |
| U2 | 1027 | `unsafe { walk_leaf_in(s().pml4_phys, None, va, create, huge, user) } } ` |
| U2 | 1034 | `unsafe fn walk_leaf_in( root: u64, as_slot: Option<u8>,` |
| U2 | 1049 | `let entry = unsafe { &mut (*table).0[idx(va, level)] as *mut u64 }; if level == stop { return Some(entry);` |
| U2 | 1054 | `let cur = unsafe { *entry }; if cur & P_PRESENT == 0 { if !create {` |
| U2 | 1060 | `unsafe { *entry = new_table_frame_in(as_slot)? \| P_PRESENT \| P_WRITE \| share }; } else if cur & P_HUGE != 0` |
| U2 | 1070 | `unsafe { *entry = cur \| P_USER }; } // SAFETY: 表项里的物理地址经 HHDM 可达` |
| U2 | 1073 | `table = unsafe { ((*entry & ADDR_MASK) + hhdm) as *mut Page }; level -= 1; }` |
| U2 | 1094 | `let e = unsafe { walk_leaf_in(root, as_slot, va, true, huge, user).ok_or(MmError::OutOfMemory)? }; // SAFETY: ` |
| U2 | 1096 | `if unsafe { *e } & P_PRESENT != 0 { return Err(MmError::AlreadyMapped); }` |
| U2 | 1100 | `unsafe { *e = value }; Ok(()) }` |
| U2 | 1115 | `unsafe { let mut table = (st.pml4_phys + hhdm) as *const Page; for level in (1u8..=3u8).rev() {` |
| U1 | 1408 | `unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nomem)) }; core::sync::atomic::compiler_fence(Ord` |
| U2 | 1414 | `if let Some(e) = unsafe { walk_leaf(va.0, false, false, false) } { // SAFETY: walk_leaf 只返回有效表项 unsafe { *e = ` |
| U2 | 1416 | `unsafe { *e = 0 }; tlb_invalidate(va.0); }` |
| U2 | 1442 | `unsafe { let mut table = (s().pml4_phys + hhdm) as *const Page; let mut level = 3u8;` |
| U1 | 1492 | `let root = unsafe { aspace_cr3_read() }; effective_flags_in(root, va) }` |
| U2 | 1554 | `unsafe { let mut table = (root + hhdm) as *const Page; let mut level = 3u8;` |
| U2 | 1609 | `unsafe { let mut table = (root + hhdm) as *const Page; let mut level = 3u8;` |
| U2 | 1638 | `unsafe { let mut table = (s().pml4_phys + hhdm) as *const Page; let mut level = 3u8;` |
| U2 | 1675 | `let pd_entry: *mut u64 = unsafe { let mut table = (s().pml4_phys + hhdm) as *mut Page; let e3 = &mut (*table).` |
| U2 | 1696 | `let old = unsafe { *pd_entry }; if old & P_PRESENT == 0 { return Err(MmError::NotMapped);` |
| U2 | 1714 | `unsafe { let pt_page = (pt_phys + hhdm) as *mut Page; for k in 0..512u64 {` |
| U2 | 1723 | `unsafe { *pd_entry = new_pd }; tlb_invalidate(block); shootdown_others(block);` |
| U4 | 1850 | `unsafe impl Sync for AspaceCell {}  static ASPACES: AspaceCell = AspaceCell(UnsafeCell::new(AspaceTable { item` |
| U4 | 1866 | `unsafe { &mut *ASPACES.0.get() } } ` |
| U2 | 1902 | `unsafe { let mine = (e.pml4 + hhdm) as *const Page; let kernel = (s().pml4_phys + hhdm) as *const Page;` |
| U2 | 1924 | `unsafe { let mine = (e.pml4 + hhdm) as *const Page; Some((0..256).filter(\|&i\| (*mine).0[i] & P_PRESENT != 0)` |
| U2 | 1958 | `unsafe { let mine = (pml4 + hhdm) as *mut Page; core::ptr::write_bytes(mine as *mut u8, 0, PAGE);` |
| U2 | 2125 | `let leaf = unsafe { walk_leaf_in(e.pml4, None, va.0, false, false, false)? }; // SAFETY: 上一行返回的是有效表项指针 let v =` |
| U2 | 2127 | `let v = unsafe { *leaf }; if v & P_PRESENT == 0 { None } else { Some(v) } }` |
| U2 | 2189 | `if let Some(leaf) = unsafe { walk_leaf_in(self.root, None, a, false, false, false) } { // SAFETY: 上一行返回的是有效表项指` |
| U2 | 2191 | `unsafe { *leaf = 0 }; tlb_invalidate(a); // 清完叶子才等回执，回执收齐之前不还帧（ADR-023/072）。` |
| U2 | 2315 | `if let Some(leaf) = unsafe { walk_leaf_in(root, None, a, false, false, false) } { // SAFETY: 上一行返回的是有效表项指针 if ` |
| U2 | 2317 | `if unsafe { *leaf } & P_PRESENT != 0 { return Err(MmError::AlreadyMapped); }` |
| U2 | 2335 | `if let Some(leaf) = unsafe { walk_leaf_in(root, None, b, false, false, false) } { // SAFETY: 有效表项指针 unsafe { *` |
| U2 | 2337 | `unsafe { *leaf = 0 }; tlb_invalidate(b); }` |
| U1 | 2383 | `pub unsafe fn aspace_switch(pml4: u64, me: usize, as_slot: Option<u8>) -> bool { // SAFETY: 读 CR3 是特权读，调用方在 ri` |
| U1 | 2385 | `let cur = unsafe { aspace_cr3_read() }; if cur == pml4 { return false;` |
| U1 | 2390 | `unsafe { aspace_cr3_write(pml4) }; CR3_WRITES.fetch_add(1, Ordering::Relaxed); // ADR-072：登记"这颗 CPU 曾跑过这个 AS"。` |
| U2 | 2407 | `pub unsafe fn aspace_switch_kernel(me: usize) -> bool { // SAFETY: our_cr3 是启动时建的内核表，前提由 take_over 保证；内核表没有 AS` |
| U2 | 2409 | `unsafe { aspace_switch(our_cr3(), me, None) } } ` |
| U4 | 2453 | `unsafe impl Sync for LazyCell {}  static LAZY: LazyCell = LazyCell(UnsafeCell::new(LazyTable { items: [LAZY_EM` |
| U4 | 2459 | `unsafe { &mut *LAZY.0.get() } } ` |
| U2 | 2557 | `unsafe { core::ptr::write_bytes((p + s().hhdm) as *mut u8, 0, PAGE) }; // 竞争变体（ADR-067 验收⑥的确定性构造）：把"已查未填 → 分配 ` |
| U2 | 2738 | `unsafe { let e = &mut *arr.add(f as usize); e.refcnt = AtomicU32::new(if used { 1 } else { 0 });` |
| U2 | 2773 | `unsafe { (*arr.add(f as usize)).refcnt.load(Ordering::Relaxed) } } ` |
| U2 | 2781 | `unsafe { (*arr.add(f as usize)).owner } } ` |
| U2 | 2789 | `unsafe { let e = &mut *arr.add(f as usize); e.refcnt.store(if used { 1 } else { 0 }, Ordering::Relaxed);` |
| U2 | 2802 | `unsafe { (*arr.add(f as usize)).refcnt.fetch_add(1, Ordering::Relaxed); } } ` |
| U2 | 2810 | `unsafe { (*arr.add(f as usize)).refcnt.fetch_sub(1, Ordering::Relaxed); } } ` |
| U2 | 2835 | `unsafe { let e = &mut *arr.add(frame as usize); if e.flags & FI_USED == 0 {` |
| U2 | 2854 | `unsafe { (*arr.add(frame as usize)).flags & FI_SEALED != 0 } } ` |
| U2 | 2918 | `unsafe { core::ptr::write_bytes(ptr, 0, cap) }; Ok(KBuf { frames, ptr, len: bytes }) }` |
| U2 | 2938 | `unsafe { core::slice::from_raw_parts(self.ptr, self.len) } } pub fn as_mut_slice(&mut self) -> &mut [u8] {` |
| U2 | 2942 | `unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) } } }` |
| U2 | 3015 | `unsafe { core::ptr::write_volatile((st.hhdm + base + b) as *mut u8, 0xa5) }; } if !ledger_free(owner, 1) {` |
| U2 | 3063 | `unsafe { core::ptr::write_volatile((st.hhdm + base.0 + b) as *mut u8, 0xa5) }; } if !ledger_free(owner, n) {` |

### memory/vmo

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 90 | `unsafe impl Sync for VmoCell {}  static T: VmoCell = VmoCell(core::cell::UnsafeCell::new(VmoTable {` |
| U4 | 102 | `unsafe { &mut *T.0.get() } } ` |
| U2 | 160 | `unsafe { core::ptr::write_bytes((pa + hhdm) as *mut u8, 0, PAGE) }; frames[got] = pa / PAGE as u64; got += 1;` |
| U2 | 273 | `unsafe { core::ptr::copy(src.as_ptr().add(done), (pa + hhdm) as *mut u8, k) }; done += k; }` |
| U2 | 306 | `unsafe { core::ptr::copy((pa + hhdm) as *const u8, dst.as_mut_ptr().add(done), k) }; done += k; }` |

### network/arp_table

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 28 | `unsafe impl Sync for ArpCell {} static ARP: ArpCell = ArpCell(core::cell::UnsafeCell::new(ArpTable { ips: [[0;` |
| U4 | 38 | `let t = unsafe { &mut *ARP.0.get() }; let mut i = 0usize; while i < t.n {` |
| U4 | 54 | `let t = unsafe { &mut *ARP.0.get() }; t.learns += 1; let mut i = 0usize;` |
| U4 | 85 | `let t = unsafe { &*ARP.0.get() }; ArpStats { hits: t.hits, misses: t.misses, learns: t.learns, evicts: t.evict` |
| U4 | 94 | `let t = unsafe { &*ARP.0.get() }; let mut n = 0usize; let mut i = cursor as usize;` |
| U4 | 110 | `let t = unsafe { &*ARP.0.get() }; t.n as u32 }` |

### sched/mod

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 582 | `unsafe impl Sync for QueueCell {} static RQ: [QueueCell; crate::arch::x86_64::cpu::MAX_CPUS] = [const { QueueC` |
| U4 | 603 | `unsafe { &*self.cell.data.get() } } }` |
| U4 | 610 | `unsafe { &mut *self.cell.data.get() } } }` |
| U4 | 827 | `unsafe { (*RQ[cpu].data.get()).current } } ` |
| U1 | 1090 | `unsafe { core::arch::asm!("int {}", const crate::arch::x86_64::trap::VEC_RESCHED) }; } ` |
| U2 | 1141 | `Some(unsafe { core::ptr::read_volatile((f as usize + RFLAGS_OFF) as *const u64) }) } ` |
| U4 | 1151 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].owned.count() } } ` |
| U4 | 1162 | `Some(unsafe { (*RQ[cpu_of(task)].data.get()).tasks[slot_of(task)].frame }) } ` |
| U4 | 1247 | `unsafe impl Sync for IdleStackCell {} static IDLE_STACKS: [IdleStackCell; crate::arch::x86_64::cpu::MAX_CPUS] ` |
| U1 | 1291 | `unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }; } }` |
| U2 | 1446 | `unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) }; } let gi = gidx(cpu, slot);` |
| U2 | 1525 | `unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) }; } s.entries[slot] = Some(entry);` |
| U2 | 1589 | `unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) }; } s.entries[slot] = None; // 用户任务没有内核入口函数` |
| U4 | 2158 | `Some(unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].on_cpu as usize }) } ` |
| U4 | 2167 | `let t = unsafe { &(*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)] }; if t.stack_lo == 0 { return None;` |
| U4 | 2184 | `let t = unsafe { &(*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)] }; if t.kstack_hi == 0 { return None;` |
| U4 | 2196 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].state } } ` |
| U2 | 2218 | `unsafe { core::ptr::write_volatile((f as usize + 10 * 8) as *mut u64, arg) }; true }` |
| U4 | 2229 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].user } } ` |
| U4 | 2241 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].resident } } ` |
| U4 | 2303 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].as_slot } } ` |
| U4 | 2314 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].id } } ` |
| U4 | 2327 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].proc_id } } ` |
| U4 | 2335 | `unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].runs } } ` |
| U2 | 2374 | `pub unsafe fn preempt_point(frame: u64, cpu: usize) { // 不跑调度器的 CPU 直接把标志倒掉再返回。今天 AP 的中断根本不经过这里 // （`isr_stub_` |
| U2 | 2465 | `unsafe { mm::aspace_switch(target, cpu, next_as_slot) }; // 换出去的那次中断不会经过异常桩出口，所以在这里替它记账（见 trap::p3_record_irq）` |
| U1 | 2489 | `unsafe { p1_extra_flush(frame) }; crate::tsc::spin(20_000); }` |
| U1 | 2538 | `unsafe { context_load(resume, if_open as u64) } } ` |
| U2 | 2571 | `unsafe { preempt_point(frame, cpu) } } ` |

### sched/proc

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 115 | `unsafe impl Sync for StateCell {}  static S: StateCell = StateCell(core::cell::UnsafeCell::new(ProcState {` |
| U4 | 125 | `unsafe { &mut *S.0.get() } } ` |
| U4 | 132 | `unsafe { &*S.0.get() } } ` |

### sched/user

| 类别 | 行 | 形状 |
|---|---|---|
| U2 | 923 | `let got = unsafe { core::slice::from_raw_parts(phys.via_hhdm().0 as *const u8, take) }; if got != &want[..take` |
| U4 | 2769 | `unsafe impl Sync for ProgCell {} static PROG_PTR: ProgCell = ProgCell(core::cell::UnsafeCell::new(None)); ` |
| U2 | 2860 | `unsafe { core::ptr::write_bytes(f.base().via_hhdm().0 as *mut u8, 0, mm::PAGE); core::ptr::write_volatile(` |
| U4 | 2950 | `return Ok(unsafe { (*PROG_PTR.0.get()).as_ref().unwrap() }); } // 先有落脚页，再建用户任务：`init` 建的镜像不再是 kill 的前提，但它自己也要有` |
| U2 | 2974 | `unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), cf.base().via_hhdm().0 as *mut u8, bytes.len()); // 三个` |
| U4 | 3003 | `unsafe { *PROG_PTR.0.get() = Some(p); PROG.store(1, Ordering::Release);` |
| U4 | 3012 | `Ok(unsafe { (*PROG_PTR.0.get()).as_ref().unwrap() }) } ` |
| U4 | 3061 | `unsafe { (*PROG_PTR.0.get()).as_ref() } } ` |
| U4 | 3353 | `unsafe impl Sync for Scratch {} static SCRATCH: Scratch = Scratch(core::cell::UnsafeCell::new([0u8; COPY_MAX])` |
| U5 | 3399 | `let got = unsafe { ucopy_from(dst.as_mut_ptr().add(done), at as *const u8, want) }; done += got; if got < want` |
| U5 | 3426 | `let got = unsafe { ucopy_to(at as *mut u8, src.as_ptr().add(done), want) }; done += got; if got < want {` |
| U2 | 3480 | `unsafe { let kva = mm::PhysAddr(pa + (at % pg)).via_hhdm(); core::ptr::write_volatile(kva.0 as *mut u8, src[do` |
| U4 | 3507 | `let buf = unsafe { &mut *SCRATCH.0.get() }; for (j, b) in buf[..len].iter_mut().enumerate() { *b = poke_patter` |
| U5 | 3516 | `let got = unsafe { ucopy_to(at as *mut u8, buf.as_ptr().add(done), want) }; done += got; if got < want {` |
| U4 | 3552 | `let buf = unsafe { &mut *SCRATCH.0.get() }; let mut done = 0usize; while done < len {` |
| U5 | 3558 | `let got = unsafe { ucopy_from(buf.as_mut_ptr().add(done), at as *const u8, want) }; done += got; if got < want` |
| U5 | 3579 | `let buf = unsafe { &mut *SCRATCH.0.get() }; unsafe { ucopy_from(buf.as_mut_ptr(), va as *const u8, len) } })` |
| U5 | 3580 | `unsafe { ucopy_from(buf.as_mut_ptr(), va as *const u8, len) } }) }` |
| U1 | 3606 | `unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) f, options(nomem, preserves_flags)) }; f & (1 << 18) !=` |
| U2 | 3733 | `unsafe { core::ptr::write_bytes(fill as *mut u8, 0, mm::PAGE) }; if copy > 0 { let at = seg.offset + page_in_s` |
| U2 | 3741 | `unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), fill as *mut u8, copy) }; } }` |
| U2 | 3765 | `unsafe { core::ptr::write_volatile(sf.base().via_hhdm().0 as *mut u64, 0) }; let m = mm::map(VirtAddr(stack_va` |
| U2 | 3838 | `unsafe { core::ptr::write_bytes(fill as *mut u8, 0, mm::PAGE) }; if copy > 0 { let at = seg.offset + page_in_s` |
| U2 | 3845 | `unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), fill as *mut u8, copy) }; } // `aspace_map_slot` 收的是**帧号` |
| U2 | 3879 | `unsafe { core::ptr::write_bytes(stack_frames.base().via_hhdm().0 as *mut u8, 0, 8 * mm::PAGE) }; let mut pas: ` |
| U2 | 3986 | `let b = unsafe { let kva = mm::PhysAddr(pa + (at % pg)).via_hhdm(); core::ptr::read_volatile(kva.0 as *const u` |

### security/cred

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 104 | `unsafe impl Sync for Cell {}  static TABLE: Cell = Cell(core::cell::UnsafeCell::new(Table {` |
| U4 | 122 | `let t = unsafe { &mut *TABLE.0.get() }; let mut slot = CRED_MAX; let mut i = 0usize;` |
| U4 | 168 | `let t = unsafe { &mut *TABLE.0.get() }; t.stats.lookups = t.stats.lookups.wrapping_add(1); let slot = id.slot ` |
| U4 | 195 | `let t = unsafe { &mut *TABLE.0.get() }; t.stats.denies = t.stats.denies.wrapping_add(1); false` |
| U4 | 207 | `let t = unsafe { &*TABLE.0.get() }; t.n as u32 }` |
| U4 | 220 | `let t = unsafe { &*TABLE.0.get() }; const REC: usize = 28; let mut n = 0usize;` |
| U4 | 250 | `let t = unsafe { &*TABLE.0.get() }; t.stats }` |

### sync/mod

| 类别 | 行 | 形状 |
|---|---|---|
| U4 | 134 | `unsafe impl Sync for OpsCell {} fn no_current() -> usize { usize::MAX } fn no_block(_: usize, _: WaitToken) ->` |
| U4 | 149 | `unsafe { *WAIT_OPS.0.get() = o; } } ` |
| U4 | 154 | `unsafe { &*WAIT_OPS.0.get() } } ` |
| U4 | 375 | `unsafe impl<T: Send> Sync for IrqSpinLock<T> {}  #[must_use = "丢弃守卫会立即释放锁，等于什么都没锁（§7.1 R16）"]` |
| U4 | 397 | `unsafe { &mut *self.lock.data.get() } } }` |
| U4 | 408 | `unsafe { self.lock.locked.store(0, Ordering::Release) }; restore_flags(self.flags); }` |
| U1 | 419 | `unsafe { core::arch::asm!( "pushfq",` |
| U1 | 438 | `unsafe { core::arch::asm!("sti", options(nomem, nostack)) }; } ` |
| U1 | 444 | `unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; } ` |
| U1 | 450 | `unsafe { core::arch::asm!("push {r}", "popfq", r = in(reg) f) }; } ` |

### testing/ktest

| 类别 | 行 | 形状 |
|---|---|---|
| U6 | 61 | `let tests = unsafe { core::slice::from_raw_parts(start as *const KTest, bytes / size) };  let mut passed = 0us` |

### time/tsc

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 31 | `unsafe { core::arch::asm!( "rdtsc",` |

### user/execprobe

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 63 | `unsafe { core::arch::asm!( "lea {}, [rip + {sym}]",` |
| U1 | 78 | `unsafe { core::arch::asm!( "lea {}, [rip + {sym}]",` |
| U5 | 91 | `unsafe { core::slice::from_raw_parts((msgs_base() + m.0 as u64) as *const u8, m.1) } } ` |
| U5 | 106 | `let b = [unsafe { *table.get_unchecked(nib) }]; let _ = rt::console_write(out, &b); }` |
| U5 | 129 | `let chunk = unsafe { core::slice::from_raw_parts_mut(chunk_base(), 4096) }; let hn = match rt::file_read(fh, c` |
| U5 | 243 | `let job = match unsafe { rt::handle_of_role(si_va, rt::ROLE_JOB) } { Some(h) => h, None => fail(out, M_ERR, -8` |
| U1 | 403 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |
| U5 | 411 | `let stdout = match unsafe { rt::handle_of_role(si_va, rt::ROLE_STDOUT) } { Some(h) => h, None => rt::exit(11),` |
| U5 | 416 | `let args = match unsafe { rt::args_at(si_va) } { Some(a) if !a.is_empty() => a, _ => rt::exit(22),` |

### user/fileprobe

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 109 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |
| U1 | 117 | `unsafe { core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym SLOTS, options(nomem, nostack, preser` |
| U1 | 126 | `unsafe fn sys3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 { let ret: u64; // SAFETY: 只有内核能处理这条中断；号走 rax、参数 rdi` |
| U1 | 130 | `unsafe { core::arch::asm!( "int 0x80",` |
| U5 | 147 | `unsafe { core::ptr::write_volatile((slots_base() + off) as *mut u64, v) }; } ` |
| U5 | 152 | `unsafe { core::ptr::write_volatile((slots_base() + off) as *mut u8, b) }; } ` |
| U5 | 157 | `unsafe { core::ptr::read_volatile((slots_base() + off) as *const u8) } } ` |
| U5 | 162 | `unsafe { core::ptr::read_volatile((slots_base() + off) as *const u32) } } ` |
| U5 | 229 | `let n = unsafe { sys3(SYS_FILE_READ, h, slots_base() + off + total, cap - total) }; last = n; if (n as i64) <=` |
| U5 | 247 | `let n = unsafe { sys3(SYS_DIR_READ, h, slots_base() + BUF_DIR, 512) }; if (n as i64) <= 0 \|\| records >= 64 {` |
| U5 | 269 | `unsafe { put(SLOT_ABI, sys3(SYS_ABI_INFO, 0, 0, 0)); ` |
| U5 | 365 | `let _ = unsafe { sys3(SYS_EXIT, 0, 0, 0) }; } }` |

### user/hello

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 115 | `unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) }; rsp & !0xf` |
| U1 | 148 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |
| U1 | 265 | `unsafe fn syscall_fast(nr: u64, a1: u64, a2: u64) -> u64 { let ret: u64; let mut c0: u64;` |
| U1 | 270 | `unsafe { core::arch::asm!( "syscall",` |
| U1 | 291 | `unsafe { core::arch::asm!("mov {}, cs", out(reg) v, options(nomem, nostack, preserves_flags)) }; v as u64 }` |
| U1 | 299 | `unsafe { core::arch::asm!("mov {}, ss", out(reg) v, options(nomem, nostack, preserves_flags)) }; v as u64 }` |
| U1 | 309 | `unsafe fn syscall(nr: u64, a1: u64, a2: u64) -> u64 { let ret: u64; // SAFETY: 见上。`preserves_flags` 是对的：中断门在内核` |
| U1 | 313 | `unsafe { core::arch::asm!( "int 0x80",` |
| U1 | 337 | `unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 { let ret: u64; // SAFETY: 同 `syscall`；rdx 只是第三个` |
| U1 | 340 | `unsafe { core::arch::asm!( "int 0x80",` |
| U5 | 359 | `let n = unsafe { syscall(SYS_PING, 0, 0) }; SLOTS.ping.store(n, Ordering::Relaxed); // **P7 归因的换位实验**（第一次归因给出 ` |
| U5 | 368 | `let _ = unsafe { syscall(SYS_PING, 1, 0) }; // 2) 参数确实穿过边界：0x2a + 0x12 = 0x3c let sum = unsafe { syscall(SYS_A` |
| U5 | 370 | `let sum = unsafe { syscall(SYS_ADD, 0x2a, 0x12) }; SLOTS.add.store(sum, Ordering::Relaxed); // 3) 没人认领的号必须回 -1` |
| U5 | 373 | `let bad = unsafe { syscall(SYS_NOBODY, 0, 0) }; SLOTS.unknown.store(bad, Ordering::Relaxed); // 读一次 .rodata 再写` |
| U5 | 382 | `let _ = unsafe { syscall(SYS_PING, n, 0) }; n += 1; }` |
| U5 | 401 | `let good = unsafe { syscall(SYS_PEEK, core::ptr::addr_of!(probe) as u64, 0) }; SLOTS.peek_ok.store(good, Order` |
| U5 | 404 | `if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(probe)) } == 0 { SLOTS.peek_ok.store(0, Ordering::Rel` |
| U5 | 407 | `let kern = unsafe { syscall(SYS_PEEK, 0xffff_ffff_8000_0000, 0) }; SLOTS.peek_kernel.store(kern, Ordering::Rel` |
| U5 | 413 | `let unmapped = unsafe { syscall(SYS_PEEK, guard, 0) }; SLOTS.peek_unmapped.store(unmapped, Ordering::Relaxed);` |
| U5 | 425 | `let n = unsafe { syscall(SYS_POKE_BUF, ptr, BUF_LEN) }; SLOTS.buf_n.store(n, Ordering::Relaxed); let mut ok: u` |
| U5 | 431 | `let v = unsafe { core::ptr::read_volatile((ptr + j) as *const u8) }; if v != poke_pattern(j) { ok = 0x1000 + j` |
| U5 | 448 | `unsafe { core::ptr::write_volatile((ptr + j) as *mut u8, write_pattern(j)) }; j += 1; }` |
| U5 | 451 | `let sum = unsafe { syscall(SYS_PEEK_BUF, ptr, BUF_LEN) }; SLOTS.buf_sum.store(sum, Ordering::Relaxed); // 3) 故` |
| U5 | 457 | `let err = unsafe { syscall(SYS_PEEK_BUF, ptr, COPY_MAX + 1) }; SLOTS.buf_err.store(err, Ordering::Relaxed); }` |
| U5 | 463 | `let word = unsafe { syscall(SYS_ABI_INFO, 0, 0) }; SLOTS.abi_word.store(word, Ordering::Relaxed); if word & F_` |
| U5 | 466 | `let n = unsafe { syscall_fast(SYS_PING, 0, 0) }; SLOTS.fast_ping.store(n, Ordering::Relaxed); SLOTS.fast_cs.st` |
| U5 | 472 | `let _ = unsafe { syscall_fast(SYS_PING, k, 0) }; k += 1; }` |
| U5 | 485 | `let n = unsafe { syscall3(SYS_FILE_READ, h, ptr, 4) }; let magic = if n == 4 { // SAFETY: `ptr` 指向本任务栈上这 4 个字节` |
| U5 | 488 | `(unsafe { core::ptr::read_volatile(ptr as *const u32) }) as u64 } else { 0xdead_0000 \| (n & 0xffff)` |
| U5 | 494 | `let _ = unsafe { syscall(SYS_HANDLE_CLOSE, h, 0) }; // 最后一个写：内核等这一格非 0 才读上面三格 SLOTS.h_done.store(HANDLE_DONE, ` |
| U5 | 504 | `unsafe { core::ptr::write_volatile(p, 0xdead) }; // 写成功了 = 隔离没生效。这里不猜结论：把"居然成功了"这件事写回槽位， // 由内核侧的判据去红（红得有数字，而不` |
| U5 | 510 | `let _ = unsafe { syscall(SYS_EXIT, 0, 0) }; // 正常不会回到这里：内核标了 Free 并把 CPU 换给别人了。 // 万一回来了（退出请求被吞掉），就停在自跳转里，等旁观者` |
| U1 | 516 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |
| U1 | 525 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |

### user/probe

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 141 | `unsafe { core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym SLOTS, options(nomem, nostack, preser` |
| U1 | 152 | `unsafe { core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym SRC, options(nomem, nostack, preserve` |
| U5 | 162 | `unsafe { let p = (slots_base() + off) as *const AtomicU64; (*p).store(v, Ordering::Release);` |
| U1 | 169 | `unsafe fn sys4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 { let ret: u64; // SAFETY: 只有内核能处理这条中断；号走 r` |
| U1 | 173 | `unsafe { core::arch::asm!( "int 0x80",` |
| U1 | 192 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |
| U5 | 227 | `unsafe { let proc_h = sys4(SYS_PROCESS_CREATE, job_h, 0, 0, 0); put(OFF_PROC_H, proc_h);` |
| U5 | 304 | `unsafe { let abi = sys4(SYS_ABI_INFO, 0, 0, 0, 0); put(OFF_ABI, abi);` |
| U5 | 324 | `if unsafe { core::ptr::read_volatile(p.add(i)) } != PATTERN[i] { ok = 0; }` |
| U5 | 359 | `if unsafe { core::ptr::read_volatile(p.add(i)) } != PATTERN[i] { x_read = 0; }` |
| U5 | 377 | `let v = unsafe { core::ptr::read_volatile(mailbox as *const u64) }; if v != 0 { job_h = v;` |
| U1 | 396 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |

### user/runtime

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 289 | `unsafe fn syscall_abi(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 { let ret: i64; // SAFETY: 只有内核能处理这条` |
| U1 | 295 | `unsafe { core::arch::asm!( "int 0x80",` |
| U5 | 318 | `let ret = unsafe { syscall_abi(SYS_PING, 0, 0, 0, 0) }; if ret < 0 { // 1 号今天的分派不会回负数（user.rs:1803）；真出现说明 ABI ` |
| U5 | 334 | `let _ = unsafe { syscall_abi(SYS_EXIT, code, 0, 0, 0) }; loop { core::hint::spin_loop();` |
| U5 | 346 | `let ret = unsafe { syscall_abi(SYS_ABI_INFO, 0, 0, 0, 0) }; ret as u64 }` |
| U5 | 357 | `let ret = unsafe { syscall_abi(SYS_HANDLE_CLOSE, h, 0, 0, 0) }; ret_zero(ret) }` |
| U5 | 365 | `let ret = unsafe { syscall_abi(SYS_HANDLE_DUP, h, rights as u64, 0, 0) }; if ret < 0 { Err(RTError(ret))` |
| U5 | 390 | `let ret = unsafe { syscall_abi(SYS_FILE_READ, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0) }; ret_len(ret)` |
| U5 | 408 | `let ret = unsafe { syscall_abi(SYS_FILE_OPEN, path.as_ptr() as u64, path.len() as u64, flags, 0) }; if ret < 0` |
| U1 | 442 | `pub unsafe fn handle_of_role(si_va: u64, role: u32) -> Option<Handle> { let base = si_va as *const u8; // SAFE` |
| U5 | 445 | `let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) }; if magic != SI_MAGIC {` |
| U5 | 449 | `let n = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_NHANDLES) as *const u32) } as usize; let n = if n >` |
| U5 | 452 | `let d = unsafe { base.add(SI_OFF_HANDLES + i * SI_DESC_BYTES) }; let r = unsafe { core::ptr::read_unaligned(d.` |
| U5 | 453 | `let r = unsafe { core::ptr::read_unaligned(d.add(SI_DESC_ROLE) as *const u32) }; if r == role { return Some(un` |
| U5 | 455 | `return Some(unsafe { core::ptr::read_unaligned(d.add(SI_DESC_HANDLE) as *const u64) }); } }` |
| U1 | 467 | `pub unsafe fn args_at(si_va: u64) -> Option<&'static [u8]> { let base = si_va as *const u8; // SAFETY: 见上；头 24` |
| U5 | 470 | `let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) }; if magic != SI_MAGIC {` |
| U5 | 474 | `let off = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_ARGS_OFF) as *const u32) } as usize; let len = un` |
| U5 | 475 | `let len = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_ARGS_LEN) as *const u32) } as usize; if off == 0 ` |
| U5 | 480 | `Some(unsafe { core::slice::from_raw_parts(base.add(off) as *const u8, len) }) } ` |
| U5 | 494 | `let ret = unsafe { syscall_abi(SYS_VMO_CREATE, pages as u64, 0, 0, 0) }; if ret < 0 { Err(RTError(ret))` |
| U5 | 509 | `let ret = unsafe { syscall_abi(SYS_VMO_WRITE, h, off, buf.as_ptr() as u64, buf.len() as u64) }; if ret < 0 { E` |
| U5 | 522 | `let ret = unsafe { syscall_abi(SYS_ASPACE_MAP, vmo, flags, proc, va) }; if ret < 0 { Err(RTError(ret))` |
| U5 | 585 | `let ret = unsafe { syscall_abi( SYS_PROC_ENUM,` |
| U5 | 625 | `let ret = unsafe { syscall_abi(SYS_PROC_STAT, proc, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };` |
| U5 | 671 | `let ret = unsafe { syscall_abi(SYS_FILE_SEEK, h, offset as u64, whence.0 as u64, 0) }; if ret < 0 { Err(RTErro` |
| U5 | 712 | `let ret = unsafe { syscall_abi(SYS_FILE_STAT, h, rec.bytes.as_mut_ptr() as u64, rec.bytes.len() as u64, 0) };` |
| U5 | 732 | `let ret = unsafe { syscall_abi(SYS_DIR_READ, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0) }; ret_len(ret) ` |
| U5 | 871 | `let ret = unsafe { syscall_abi(SYS_CONSOLE_WRITE, h, buf.as_ptr() as u64, buf.len() as u64, 0) }; ret_len(ret)` |
| U5 | 888 | `let ret = unsafe { syscall_abi(SYS_CONSOLE_READ, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0) }; ret_len(r` |
| U5 | 900 | `let ret = unsafe { syscall_abi(SYS_PROCESS_CREATE, job, 0, 0, 0) }; if ret < 0 { Err(RTError(ret))` |
| U5 | 917 | `let ret = unsafe { syscall_abi(SYS_THREAD_CREATE, proc_h, entry, stack_top, arg) }; if ret < 0 { Err(RTError(r` |
| U5 | 934 | `let ret = unsafe { syscall_abi(SYS_PROCESS_START, proc_h, thread, si_vmo, si_va) }; ret_zero(ret) }` |
| U5 | 970 | `let ret = unsafe { syscall_abi(SYS_PROCESS_WAIT, proc_h, timeout_ms, 0, 0) }; decode_wait(ret) }` |
| U5 | 979 | `let ret = unsafe { syscall_abi(SYS_PROCESS_KILL, proc_h, 0, 0, 0) }; if ret < 0 { Err(RTError(ret))` |
| U5 | 992 | `let ret = unsafe { syscall_abi(SYS_PROC_KILL_BY_PID, u64::from(pid), 0, 0, 0) }; if ret < 0 { Err(RTError(ret)` |
| U5 | 1011 | `let ret = unsafe { syscall_abi(SYS_LOG_READ, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0) };` |
| U5 | 1032 | `let ret = unsafe { syscall_abi(SYS_PCI_ENUM, buf.as_mut_ptr() as u64, cursor, 0, buf.len() as u64) };` |
| U5 | 1046 | `let ret = unsafe { syscall_abi(SYS_CLOCK_UPTIME, 0, 0, 0, 0) }; if ret < 0 { Err(RTError(ret))` |
| U5 | 1071 | `let ret = unsafe { syscall_abi(SYS_OBJECT_WAIT, h, signals, timeout_ms, 0) }; decode_wait(ret) }` |
| U1 | 1114 | `pub unsafe fn find_console(si_va: u64) -> Option<Handle> { let base = si_va as *const u8; // SAFETY: 见函数契约；只读前` |
| U5 | 1117 | `let magic = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_MAGIC) as *const u32) }; if magic != SI_MAGIC {` |
| U5 | 1122 | `let n = unsafe { core::ptr::read_unaligned(base.add(SI_OFF_NHANDLES) as *const u32) } as usize; let n = if n >` |
| U5 | 1127 | `let d = unsafe { base.add(SI_OFF_HANDLES + i * SI_DESC_BYTES) }; // SAFETY: 描述内 role 字段（u32），落在该条 16 字节内。 let ` |
| U5 | 1129 | `let role = unsafe { core::ptr::read_unaligned(d.add(SI_DESC_ROLE) as *const u32) }; if role == ROLE_LOG { // S` |
| U5 | 1132 | `return Some(unsafe { core::ptr::read_unaligned(d.add(SI_DESC_HANDLE) as *const u64) }); } }` |
| U5 | 1158 | `let ret = unsafe { syscall_abi( SYS_DNS_RESOLVE,` |
| U5 | 1192 | `let ret = unsafe { syscall_abi(SYS_FILE_WRITE, h, buf.as_ptr() as u64, buf.len() as u64, 0) } as i64;` |
| U5 | 1215 | `let ret = unsafe { syscall_abi(SYS_SYSINFO, blk.as_mut_ptr() as u64, blk.len() as u64, 0, 0) } as i64;` |
| U5 | 1235 | `let ret = unsafe { syscall_abi( SYS_FB_TEXT,` |
| U5 | 1254 | `let ret = unsafe { syscall_abi(SYS_FB_CLEAR, 0, 0, 0, 0) } as i64; ret > 0 }` |
| U5 | 1270 | `let ret = unsafe { syscall_abi( SYS_PART_ENUM,` |
| U5 | 1290 | `let ret = unsafe { syscall_abi(SYS_PART_INFO, blk.as_mut_ptr() as u64, u64::from(port), 0, 0) } as i64;` |
| U5 | 1322 | `let ret = unsafe { syscall_abi(SYS_CRED_SELF, blk.as_mut_ptr() as u64, 0, 0, 0) } as i64; if ret < 0 { Err(RTE` |
| U5 | 1332 | `let ret = unsafe { syscall_abi(SYS_CRED_LIST, u64::from(cursor), buf.len() as u64, 0, buf.as_mut_ptr() as u64)` |
| U5 | 1344 | `let ret = unsafe { syscall_abi(SYS_CRED_ALLOWS, u64::from(cap), 0, 0, 0) } as i64; if ret < 0 { Err(RTError(re` |
| U5 | 1352 | `let ret = unsafe { syscall_abi(SYS_CRED_STATS, blk.as_mut_ptr() as u64, 0, 0, 0) } as i64; if ret < 0 { Err(RT` |
| U5 | 1365 | `let ret = unsafe { syscall_abi(SYS_NET_ARP_LEN, 0, 0, 0, 0) } as i64; if ret < 0 { Err(RTError(ret)) } else { ` |
| U5 | 1375 | `let ret = unsafe { syscall_abi(SYS_NET_ARP_ENUM, u64::from(cursor), buf.len() as u64, buf.len() as u64, buf.as` |
| U5 | 1388 | `let ret = unsafe { syscall_abi(SYS_NET_SEND, frame.as_ptr() as u64, frame.len() as u64, 0, 0) }; if ret == 0 {` |
| U5 | 1398 | `let ret = unsafe { syscall_abi(SYS_NET_RECV, buf.as_mut_ptr() as u64, buf.len() as u64, timeout_ms, 0) }; Ok(r` |
| U5 | 1407 | `let ret = unsafe { syscall_abi(SYS_NET_INFO, blk.as_mut_ptr() as u64, 0, 0, 0) } as i64; if ret < 0 { Err(RTEr` |

### user/runtime/exec

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 48 | `unsafe { core::arch::asm!( "lea {}, [rip + {sym}]",` |

### user/sdkdemo

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 58 | `unsafe { core::arch::asm!( "lea {0}, [rip + {1}]",` |
| U5 | 73 | `let s = unsafe { core::slice::from_raw_parts(msgs_base().add(off), len) }; let _ = rt::console_write(h, s); }` |
| U5 | 81 | `unsafe { core::ptr::write(buf.as_mut_ptr(), b'0') }; return 1; }` |
| U5 | 89 | `unsafe { core::ptr::write(tmp.as_mut_ptr().add(n), b'0' + d) }; v /= 10; n += 1;` |
| U5 | 96 | `let src = unsafe { core::ptr::read(tmp.as_ptr().add(n - 1 - k)) }; unsafe { core::ptr::write(buf.as_mut_ptr().` |
| U5 | 97 | `unsafe { core::ptr::write(buf.as_mut_ptr().add(k), src) }; k += 1; }` |
| U5 | 149 | `unsafe { rt::find_console(si_va) } }; ` |
| U5 | 162 | `u32::from(unsafe { core::ptr::read_unaligned(rec.as_ptr().add(off)) }) }; let u = rd(5) \| (rd(6) << 8) \| (rd` |
| U5 | 180 | `unsafe { let p = core::ptr::addr_of!(SLOTS) as *mut u64; core::ptr::write_volatile(p.add(1), u64::from(uid));` |
| U5 | 205 | `let _ = rt::console_write(handle, unsafe { core::slice::from_raw_parts(num.as_ptr(), n) });` |
| U5 | 210 | `let _ = rt::console_write(handle, unsafe { core::slice::from_raw_parts(num.as_ptr(), n) });` |
| U5 | 215 | `let _ = rt::console_write(handle, unsafe { core::slice::from_raw_parts(num.as_ptr(), n) });` |

### user/shell

| 类别 | 行 | 形状 |
|---|---|---|
| U1 | 208 | `unsafe { core::arch::asm!("lea {}, [rip + {sym}]", out(reg) b, sym = sym MSGS, options(nomem, nostack, preserv` |
| U5 | 219 | `unsafe { core::slice::from_raw_parts((msgs_base() + m.0 as u64) as *const u8, m.1) } } ` |
| U1 | 229 | `unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } }` |
| U1 | 339 | `unsafe { core::arch::asm!( "lea {0}, [rip + {1}]",` |
| U5 | 354 | `unsafe { SINK_LEN = 0; SINK_TRUNC = false;` |
| U5 | 366 | `unsafe { SINK_ON = false; let base = sink_base() as *const u8;` |
| U5 | 376 | `unsafe { if !SINK_ON { return None;` |
| U5 | 474 | `let console = match unsafe { rt::find_console(si_va) } { Some(h) => h, None => {` |
| U5 | 489 | `if let Some(argv) = unsafe { rt::args_at(si_va) } { let line = argv.split(\|&b\| b == 0).next().unwrap_or(&[])` |

### user/shell/registry

| 类别 | 行 | 形状 |
|---|---|---|
| U5 | 75 | `unsafe { STDIN = s }; } ` |
| U5 | 81 | `unsafe { STDIN } } ` |
| U5 | 388 | `let job = match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_JOB) } { Some(h) => h, None => {` |
| U5 | 418 | `match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_JOB) } { Some(h) => Some(h), None => {` |
| U5 | 700 | `let sleep_h = match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_SELF_PROC) } { Some(h) => h, None => {` |
| U5 | 933 | `let h = match unsafe { rt::handle_of_role(c.si_va, rt::ROLE_SELF_PROC) } { Some(h) => h, None => {` |
