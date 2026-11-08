# unsafe 逐处审计表（U1–U6）

总计 286 处。U1 54 · U2 61 · U3 13 · U4 109 · U5 28 · U6 21

本表由 `tools/aurora.py` 的 `unsafe_sites()` 从源码逐处生成，**不是手写的**。
机器可读的权威来源是 `docs/security/unsafe-whitelist.toml` 的 `[modules.*]` 段（模块×类别→处数），
门禁 `check-unsafe` 每次从源码重算一遍与它双向对账，并核本表上面那条汇总行。
分类规则与优先序见 `_classify_unsafe()`：**类别判错了改规则，不改登记数去凑。**

## 类别

- **U1 架构入口与特殊寄存器** — 53 处，分布在 13 个模块：arch/x86_64/apic、arch/x86_64/cpu、arch/x86_64/smp、arch/x86_64/trap、hw、ktests/sched、mm、sched、serial、sync、tsc、user、user/hello
- **U2 页表、物理内存与 MMIO** — 60 处，分布在 9 个模块：acpi、arch/x86_64/apic、heap、hw、limine、mm、pci、sched、user
- **U3 DMA 与设备共享内存** — 13 处，分布在 2 个模块：driver、limine
- **U4 并发共享状态与 UnsafeCell** — 106 处，分布在 18 个模块：acpi、ahci、arch/x86_64/apic、arch/x86_64/smp、arch/x86_64/trap、driver、hooks、irq、ktests/elf、ktests/fs、ktests/sign、main、mm、pci、sched、sync、user、virtio
- **U5 用户指针与地址空间访问** — 28 处，分布在 2 个模块：user、user/hello
- **U6 诊断路径的有限现场读取** — 21 处，分布在 9 个模块：crash、ktest、ktests/acpi、ktests/crash、ktests/fs、ktests/heap、ktests/mm、ktests/sched、ktests/user

## 口径

- 一处 = 一个非注释行里的 `unsafe {` / `unsafe impl` / `unsafe fn` / `unsafe extern`。
- 本轮 273 处 = impl 个 `unsafe impl` + fn 个 `unsafe fn` + extern 个 `unsafe extern`
- 判定窗口 = 现场行与其后两行（`unsafe {` 常单独一行，操作在下一行）。
- 所属函数只认列 0 的顶层 `fn`：`extern "C" {}` 里那些缩进的 `fn` 是声明不是定义。
- 兜底类是 U2；落进兜底意味着"没有更具体的规则命中"，核对时优先看这一类。

## 逐处


### acpi

- `kernel/src/acpi.rs:188` [impl] **U4** fn=`ioapic_for`
  > unsafe impl Sync for SumCellSync {} static SUM_CELL: SumCellSync = SumCellSync(UnsafeCell::new(SumCell { inner: None }));  
- `kernel/src/acpi.rs:194` [{] **U4** fn=`sum_set`
  > unsafe { (*SUM_CELL.0.get()).inner = Some(s) }; SUMMARY.store(1, Ordering::Release); } 
- `kernel/src/acpi.rs:203` [{] **U4** fn=`summary`
  > unsafe { (*SUM_CELL.0.get()).inner } }  
- `kernel/src/acpi.rs:255` [{] **U2** fn=`read_bytes`
  > *o = unsafe { core::ptr::read_volatile((va as usize + i) as *const u8) }; } Ok(()) 
- `kernel/src/acpi.rs:427` [{] **U4** fn=`init`
  > unsafe { (*REFS.0.get())[i] = refs[i] }; } for r in refs.iter().flatten() { 
- `kernel/src/acpi.rs:621` [impl] **U4** fn=`parse_mcfg`
  > unsafe impl Sync for RefsCell {} static REFS: RefsCell = RefsCell(UnsafeCell::new([None; MAX_TABLES]));  
- `kernel/src/acpi.rs:630` [{] **U4** fn=`table`
  > unsafe { (*REFS.0.get())[i] } }  

### ahci

- `kernel/src/ahci.rs:307` [impl] **U4** fn=`—`
  > unsafe impl Sync for RingCell {} static RING: RingCell = RingCell(UnsafeCell::new(None));  
- `kernel/src/ahci.rs:464` [{] **U4** fn=`info`
  > unsafe { (*RING.0.get()).as_ref().map(|r| r.info) } }  
- `kernel/src/ahci.rs:471` [{] **U4** fn=`mmio_ref`
  > unsafe { (*RING.0.get()).as_ref().map(|r| (r.ctx, r.mmio)).ok_or(AhciError::NotClaimed) } }  
- `kernel/src/ahci.rs:477` [{] **U4** fn=`dma_ref`
  > unsafe { (*RING.0.get()).as_ref().map(|r| (r.ctx, r.dma)).ok_or(AhciError::NotClaimed) } }  
- `kernel/src/ahci.rs:666` [impl] **U4** fn=`irq_gates`
  > unsafe impl Sync for ArmCell {} static ARM: ArmCell = ArmCell(UnsafeCell::new(None));  
- `kernel/src/ahci.rs:726` [{] **U4** fn=`arm_irq`
  > unsafe { *ARM.0.get() = Some(h) }; Ok(h.vector) } 
- `kernel/src/ahci.rs:790` [{] **U4** fn=`irq_handle`
  > unsafe { *ARM.0.get() } }  
- `kernel/src/ahci.rs:807` [{] **U4** fn=`disarm_irq_for_test`
  > unsafe { *ARM.0.get() = None }; }  
- `kernel/src/ahci.rs:1102` [{] **U4** fn=`init`
  > unsafe { *RING.0.get() = Some(Ring { ctx, mmio, dma, info }) }; fill(0, 0xEE, RING_PAGES * mm::PAGE)?; Ok(info) 

### arch/x86_64/apic

- `kernel/src/arch/x86_64/apic.rs:262` [{] **U4** fn=`state`
  > unsafe { *STATE_COPY.0.get() } } else { None 
- `kernel/src/arch/x86_64/apic.rs:270` [impl] **U4** fn=`state`
  > unsafe impl Sync for StateCell {} static STATE_COPY: StateCell = StateCell(core::cell::UnsafeCell::new(None));  
- `kernel/src/arch/x86_64/apic.rs:277` [{] **U2** fn=`mmio_read32`
  > unsafe { core::ptr::read_volatile((base + off) as *const u32) } }  
- `kernel/src/arch/x86_64/apic.rs:283` [{] **U2** fn=`mmio_write32`
  > unsafe { core::ptr::write_volatile((base + off) as *mut u32, v) }; }  
- `kernel/src/arch/x86_64/apic.rs:383` [{] **U4** fn=`init`
  > unsafe { *STATE_COPY.0.get() = Some(s) }; STATE.store(1, Ordering::Release); Ok(s) 
- `kernel/src/arch/x86_64/apic.rs:598` [{] **U1** fn=`open_cpu_window`
  > unsafe { core::arch::asm!("sti", options(nomem, nostack)) }; }  
- `kernel/src/arch/x86_64/apic.rs:604` [{] **U1** fn=`close_cpu_window`
  > unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; if slot < crate::arch::x86_64::cpu::MAX_CPUS { CPU_IF[slot].store(false, Ordering::Release); 
- `kernel/src/arch/x86_64/apic.rs:625` [{] **U1** fn=`with_interrupts`
  > unsafe { core::arch::asm!("sti", options(nomem, nostack)) }; let r = f(); // SAFETY: cli 只清 EFLAGS.IF，同上 
- `kernel/src/arch/x86_64/apic.rs:628` [{] **U1** fn=`with_interrupts`
  > unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; CPU_IF[slot].store(false, Ordering::Release); r 

### arch/x86_64/cpu

- `kernel/src/arch/x86_64/cpu.rs:51` [{] **U1** fn=`enable_user_protections`
  > unsafe { core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, preserves_flags)); // 只加要加的位，绝不整份覆盖：bootloader/QEMU 可能已经放了别的位（PAE 之类） 
- `kernel/src/arch/x86_64/cpu.rs:66` [{] **U1** fn=`cr4`
  > unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, preserves_flags)) }; v } 
- `kernel/src/arch/x86_64/cpu.rs:91` [{] **U1** fn=`rdmsr`
  > unsafe { core::arch::asm!("rdmsr", in("ecx") msr, lateout("eax") lo, lateout("edx") hi, options(nomem, preserves_flags)); 
- `kernel/src/arch/x86_64/cpu.rs:101` [{] **U1** fn=`wrmsr`
  > unsafe { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nomem, preserves_flags)); 
- `kernel/src/arch/x86_64/cpu.rs:114` [{] **U1** fn=`clear_smap_for_test`
  > unsafe { let mut v: u64; core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, preserves_flags)); 

### arch/x86_64/smp

- `kernel/src/arch/x86_64/smp.rs:47` [impl] **U4** fn=`—`
  > unsafe impl Sync for ApBootCell {} static AP_ARGS: [ApBootCell; cpu::MAX_CPUS] = [const { ApBootCell(UnsafeCell::new(ApBoot { stack_top: 0, slot: 0, expect_lapic: 0 })) }; cpu::MAX_CPUS]; 
- `kernel/src/arch/x86_64/smp.rs:53` [{] **U4** fn=`ap_boot_layout`
  > let a = unsafe { &*AP_ARGS[slot].0.get() }; (a.stack_top, a.slot, a.expect_lapic) } 
- `kernel/src/arch/x86_64/smp.rs:195` [{] **U1** fn=`ap_entry_addr`
  > unsafe { ap_entry_gate[0] } }  
- `kernel/src/arch/x86_64/smp.rs:275` [{] **U4** fn=`bringup`
  > unsafe { *AP_ARGS[slot].0.get() = ApBoot { stack_top: top, slot: slot as u64, expect_lapic: lapic_id as u64 }; } 
- `kernel/src/arch/x86_64/smp.rs:281` [{] **U4** fn=`bringup`
  > unsafe { limine::release_mp_cpu(mp.cpu_ptrs[i] as *mut limine::MpInfo, AP_ARGS[slot].0.get() as u64, ap_entry_addr()); } 
- `kernel/src/arch/x86_64/smp.rs:463` [{] **U1** fn=`aurora_ap_main`
  > unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }; } // 10) 停机：先关窗口（立牌 + `cli`）再关定时器，之后不再碰任何共享状态。 
- `kernel/src/arch/x86_64/smp.rs:471` [{] **U1** fn=`aurora_ap_main`
  > unsafe { core::arch::asm!("cli", options(nomem, nostack)) }; AP_STAGE[slot].store(3, Ordering::Release); halt_forever() 
- `kernel/src/arch/x86_64/smp.rs:479` [{] **U1** fn=`halt_forever`
  > unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) }; } } 
- `kernel/src/arch/x86_64/smp.rs:529` [impl] **U4** fn=`ap_worker`
  > unsafe impl Sync for RaceCell {} static RACE: RaceCell = RaceCell(UnsafeCell::new(0));  
- `kernel/src/arch/x86_64/smp.rs:601` [{] **U4** fn=`bump`
  > unsafe { let p = RACE.0.get(); let v = core::ptr::read_volatile(p); 
- `kernel/src/arch/x86_64/smp.rs:757` [{] **U4** fn=`run_phase`
  > unsafe { core::ptr::write_volatile(RACE.0.get(), 0) }; PHASE.store(phase, Ordering::Release); // 1) 等所有 AP 声称"已进入本相位"（它们会立刻开始跑，与 BSP 重叠） 
- `kernel/src/arch/x86_64/smp.rs:775` [{] **U4** fn=`run_phase`
  > let observed = unsafe { core::ptr::read_volatile(RACE.0.get()) }; let expected = (aps.len() as u64 + 1) * RACE_ROUNDS; // 少的那一部分就是被并发覆盖掉的更新 

### arch/x86_64/trap

- `kernel/src/arch/x86_64/trap.rs:126` [{] **U4** fn=`tss_offsets`
  > unsafe { let base = core::ptr::addr_of_mut!((*TABLES[slot].0.get()).tss) as *const u8; Some(( 
- `kernel/src/arch/x86_64/trap.rs:207` [impl] **U4** fn=`tss_offsets`
  > unsafe impl Sync for TablesSlot {}  static TABLES: [TablesSlot; crate::arch::x86_64::cpu::MAX_CPUS] = [const { 
- `kernel/src/arch/x86_64/trap.rs:283` [{] **U1** fn=`init_cpu_tables`
  > let t = unsafe { &mut *TABLES[slot].0.get() };  t.gdt[0] = 0; 
- `kernel/src/arch/x86_64/trap.rs:313` [{] **U1** fn=`init_cpu_tables`
  > unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), ist1) };  let has_err = vectors_with_error_code(); 
- `kernel/src/arch/x86_64/trap.rs:325` [{] **U1** fn=`init_cpu_tables`
  > unsafe { isr_shootdown_gate[0] } } else { unsafe { isr_table[v] } 
- `kernel/src/arch/x86_64/trap.rs:327` [{] **U1** fn=`init_cpu_tables`
  > unsafe { isr_table[v] } }; t.idt[v] = idt_gate( 
- `kernel/src/arch/x86_64/trap.rs:346` [{] **U1** fn=`init_cpu_tables`
  > unsafe { core::arch::asm!("lgdt [{}]", in(reg) &gdtr); flush_segments(SEL_CODE, SEL_DATA); 
- `kernel/src/arch/x86_64/trap.rs:381` [{] **U1** fn=`install_exception_stack`
  > let t = unsafe { &mut *TABLES[slot].0.get() }; // SAFETY: packed 字段，见 `Tss` 注释；偏移由 `tss_offsets` 复核 unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), top) }; 
- `kernel/src/arch/x86_64/trap.rs:383` [{] **U1** fn=`install_exception_stack`
  > unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.ist[0]), top) }; Ok(ExStackInfo { guard_va, stack_lo, stack_hi, top }) } 
- `kernel/src/arch/x86_64/trap.rs:588` [impl] **U4** fn=`ex_stack_info`
  > unsafe impl Sync for StatsTable {} static STATS: StatsTable = StatsTable(core::cell::UnsafeCell::new([const { new_row() }; crate::arch::x86_64::cpu::MAX_CPUS]));  
- `kernel/src/arch/x86_64/trap.rs:601` [{] **U4** fn=`row`
  > unsafe { &(*STATS.0.get())[slot] } }  
- `kernel/src/arch/x86_64/trap.rs:1027` [{] **U4** fn=`set_rsp0`
  > let t = unsafe { &mut *TABLES[slot].0.get() }; // SAFETY: packed 字段必须按不可对齐的方式写（见 `Tss` 的注释：这个字段落在 // 偏移 4，而 `u64` 的自然对齐是 8，引用与直接赋值都不允许） 
- `kernel/src/arch/x86_64/trap.rs:1030` [{] **U1** fn=`set_rsp0`
  > unsafe { core::ptr::write_unaligned(core::ptr::addr_of_mut!(t.tss.rsp0), va) }; // 同一个值发布给快路径：`SYSCALL` 不查 TSS，硬件不给它换栈。 // **一个写入点喂两个消费者**，所以"rsp0 与快路径不同源"这种错法在结构上不会出现； 
- `kernel/src/arch/x86_64/trap.rs:1036` [{] **U4** fn=`set_rsp0`
  > unsafe { (*FAST_AREAS[slot].0.get()).kstack_top = va; } 
- `kernel/src/arch/x86_64/trap.rs:1062` [{] **U1** fn=`gdt_entry`
  > Some(unsafe { (*TABLES[slot].0.get()).gdt[i] }) }  
- `kernel/src/arch/x86_64/trap.rs:1078` [extern] **U1** fn=`aurora_trap_entry`
  > pub unsafe extern "C" fn aurora_trap_entry(frame: &mut TrapFrame) { // P3/P5 的下界读数（新边界见 `isr_common` 出口那段的注释：不含异常桩的寄存器保存）。 // 取完就存进本 CPU 的行，致命出口那条路径要从这里回看。 
- `kernel/src/arch/x86_64/trap.rs:1124` [{] **U1** fn=`probe_page_fault`
  > unsafe { core::arch::asm!("call pf_probe", in("rdi") addr, lateout("rax") ret, options(preserves_flags)); } 
- `kernel/src/arch/x86_64/trap.rs:1156` [{] **U1** fn=`halt_forever`
  > unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) }; } } 
- `kernel/src/arch/x86_64/trap.rs:1200` [impl] **U4** fn=`halt_forever`
  > unsafe impl Sync for FastSlotCell {} static FAST_AREAS: [FastSlotCell; crate::arch::x86_64::cpu::MAX_CPUS] = [const { FastSlotCell(core::cell::UnsafeCell::new(FastArea { 
- `kernel/src/arch/x86_64/trap.rs:1227` [{] **U4** fn=`fast_area_of`
  > let a = unsafe { &*FAST_AREAS[slot].0.get() }; Some((a.kstack_top, a.slot)) } 
- `kernel/src/arch/x86_64/trap.rs:1266` [{] **U4** fn=`install_fastpath`
  > unsafe { (*FAST_AREAS[slot].0.get()).slot = slot as u64; } 
- `kernel/src/arch/x86_64/trap.rs:1687` [{] **U1** fn=`handler_count_distinct`
  > seen[i] = unsafe { isr_table[i] }; } let mut n = 0; 

### crash

- `kernel/src/crash.rs:132` [{] **U6** fn=`walk_frames`
  > let next = unsafe { (fp as *const u64).read_volatile() }; // SAFETY: 同上，偏移在同一个已映射的帧内（rbp 指向帧头，+8 不会越出这一页的 //        可能性由下面的 `next` 自检兜住：拿回来的"链"必须是内核半区的对齐地址） 
- `kernel/src/crash.rs:135` [{] **U6** fn=`walk_frames`
  > let ret = unsafe { ((fp + 8) as *const u64).read_volatile() }; // 先记这一帧，再决定要不要往上走：这一层帧的返回地址是有效的，即使它的上一帧 // 的链断了。反过来（先验 `next` 再记）会把最后那一帧丢掉 —— 第一版就是这么少的一个帧 

### driver

- `kernel/src/driver.rs:126` [impl] **U4** fn=`—`
  > unsafe impl Sync for TableCell {} static TABLE: TableCell = TableCell(UnsafeCell::new(Table::empty()));  
- `kernel/src/driver.rs:193` [{] **U4** fn=`check_d`
  > let t = unsafe { &mut *TABLE.0.get() }; let slot = t.free_mmio_slot().ok_or(DriverError::ResourceExhausted)?; let gen = t.fresh_gen(); 
- `kernel/src/driver.rs:206` [{] **U4** fn=`check_d`
  > let e = unsafe { &*TABLE.0.get() }.mmio[i].as_ref().ok_or(DriverError::NoSuchHandle(h.slot))?; check_m(e, h.slot, h.gen, owner)?; Ok(e) 
- `kernel/src/driver.rs:255` [{] **U4** fn=`check_d`
  > match unsafe { &mut *TABLE.0.get() }.mmio[i].take() { Some(_) => Ok(()), None => Err(DriverError::NoSuchHandle(h.slot)), 
- `kernel/src/driver.rs:293` [{] **U4** fn=`check_d`
  > let t = unsafe { &mut *TABLE.0.get() }; let slot = t.free_dma_slot().ok_or(DriverError::ResourceExhausted)?; let gen = t.fresh_gen(); 
- `kernel/src/driver.rs:306` [{] **U4** fn=`check_d`
  > let e = unsafe { &*TABLE.0.get() }.dma[i].as_ref().ok_or(DriverError::NoSuchHandle(h.slot))?; check_d(e, h.slot, h.gen, owner)?; Ok(e) 
- `kernel/src/driver.rs:334` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::read_volatile(at as *const u8) }) }  
- `kernel/src/driver.rs:343` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::read_volatile(at as *const u32) }) }  
- `kernel/src/driver.rs:354` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::read_volatile(at as *const u16) }) }  
- `kernel/src/driver.rs:360` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::write_volatile(at as *mut u8, v) }) }  
- `kernel/src/driver.rs:370` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::write_volatile(at as *mut u16, v) }) }  
- `kernel/src/driver.rs:379` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::write_volatile(at as *mut u32, v) }) }  
- `kernel/src/driver.rs:393` [{] **U3** fn=`check_d`
  > unsafe { core::ptr::write_volatile(at as *mut u8, *b) }; } Ok(()) 
- `kernel/src/driver.rs:401` [{] **U3** fn=`check_d`
  > Ok(unsafe { core::ptr::write_bytes(at as *mut u8, pat, n) }) }  
- `kernel/src/driver.rs:410` [{] **U3** fn=`check_d`
  > *o = unsafe { core::ptr::read_volatile((at + i as u64) as *const u8) }; } Ok(()) 
- `kernel/src/driver.rs:423` [{] **U4** fn=`check_d`
  > match unsafe { &mut *TABLE.0.get() }.dma[i].take() { Some(_) => Ok(()), None => Err(DriverError::NoSuchHandle(h.slot)), 
- `kernel/src/driver.rs:488` [{] **U4** fn=`occupancy`
  > let t = unsafe { &*TABLE.0.get() }; (t.mmio.iter().filter(|e| e.is_some()).count(), t.dma.iter().filter(|e| e.is_some()).count()) } 
- `kernel/src/driver.rs:520` [{] **U4** fn=`mmio_gen_at`
  > unsafe { &*TABLE.0.get() }.mmio[usize::from(slot)].as_ref().map(|e| e.gen) } 

### heap

- `kernel/src/heap.rs:228` [{] **U2** fn=`try_alloc`
  > st.free[ci] = unsafe { *(p as *const usize) }; st.live_slots[ci] += 1; drop(g); 
- `kernel/src/heap.rs:262` [fn] **U2** fn=`dealloc_small`
  > pub unsafe fn dealloc_small(ptr: *mut u8, size: usize) -> bool { let Some(ci) = class_of(size) else { return false }; if refuse_if_isr("释放") { 
- `kernel/src/heap.rs:275` [{] **U2** fn=`dealloc_small`
  > unsafe { *(ptr as *mut usize) = st.free[ci] }; st.free[ci] = p; st.live_slots[ci] = st.live_slots[ci].saturating_sub(1); 
- `kernel/src/heap.rs:300` [impl] **U2** fn=`force_reentrant_lock_for_test`
  > unsafe impl GlobalAlloc for AuroraGlobal { unsafe fn alloc(&self, layout: Layout) -> *mut u8 { // 返回空指针 = 走 handle_alloc_error = L4。这是稳定版接口给的唯一选项， 
- `kernel/src/heap.rs:301` [fn] **U2** fn=`force_reentrant_lock_for_test`
  > unsafe fn alloc(&self, layout: Layout) -> *mut u8 { // 返回空指针 = 走 handle_alloc_error = L4。这是稳定版接口给的唯一选项， // 不是我们的选择；要 Result 请用 heap::try_alloc（ADR-018）。 
- `kernel/src/heap.rs:307` [fn] **U2** fn=`force_reentrant_lock_for_test`
  > unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { if ptr.is_null() { return; 
- `kernel/src/heap.rs:312` [{] **U2** fn=`force_reentrant_lock_for_test`
  > if !unsafe { dealloc_small(ptr, layout.size()) } { crate::log_fatal!("L4: dealloc 参数无法归入任何大小类 size={} ptr={:p}", layout.size(), ptr); crate::exit::finish(crate::exit::Code::ExceptionFatal); 

### hooks

- `kernel/src/hooks.rs:22` [impl] **U4** fn=`—`
  > unsafe impl Sync for HooksCell {}  fn no_mark_tick() {} 
- `kernel/src/hooks.rs:45` [{] **U4** fn=`install`
  > unsafe { *HOOKS.0.get() = h; } }  
- `kernel/src/hooks.rs:50` [{] **U4** fn=`sched`
  > unsafe { &*HOOKS.0.get() } } 

### hw

- `kernel/src/hw.rs:58` [{] **U2** fn=`—`
  > Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u8) }) }  
- `kernel/src/hw.rs:63` [{] **U2** fn=`—`
  > Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u16) }) }  
- `kernel/src/hw.rs:68` [{] **U2** fn=`—`
  > Ok(unsafe { core::ptr::read_volatile((self.base() + off as u64) as *const u32) }) }  
- `kernel/src/hw.rs:74` [{] **U2** fn=`—`
  > unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u16, v) }; Ok(()) } 
- `kernel/src/hw.rs:81` [{] **U2** fn=`—`
  > unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u8, v) }; Ok(()) } 
- `kernel/src/hw.rs:88` [{] **U2** fn=`—`
  > unsafe { core::ptr::write_volatile((self.base() + off as u64) as *mut u32, v) }; Ok(()) } 
- `kernel/src/hw.rs:99` [{] **U1** fn=`outl`
  > unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) } 
- `kernel/src/hw.rs:107` [{] **U1** fn=`inl`
  > unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags)) } 

### irq

- `kernel/src/irq.rs:109` [impl] **U4** fn=`—`
  > unsafe impl Sync for TableCell {} static TABLE: TableCell = TableCell(UnsafeCell::new(Table::empty())); /// 落进这张表之外的那几发（向量没有主人）。它是"分配与编程两边不一致"的证人。 
- `kernel/src/irq.rs:138` [{] **U4** fn=`request`
  > let t = unsafe { &mut *TABLE.0.get() }; let Some(slot) = t.slots.iter().position(|e| e.is_none()) else { return Err(IrqError::Exhausted); 
- `kernel/src/irq.rs:163` [{] **U4** fn=`release`
  > let t = unsafe { &mut *TABLE.0.get() }; let i = h.slot as usize; if i >= SLOTS { 
- `kernel/src/irq.rs:189` [{] **U4** fn=`message`
  > let t = unsafe { &*TABLE.0.get() }; t.slots[usize::from(vector) - VEC_FIRST].as_ref().map_or(st.id as u8, |e| e.dest) }; 
- `kernel/src/irq.rs:212` [{] **U4** fn=`set_affinity`
  > let t = unsafe { &mut *TABLE.0.get() }; let e = t.slots[usize::from(vector) - VEC_FIRST] .as_mut() 
- `kernel/src/irq.rs:225` [{] **U4** fn=`dest`
  > let t = unsafe { &*TABLE.0.get() }; t.slots[usize::from(vector) - VEC_FIRST] .as_ref() 
- `kernel/src/irq.rs:241` [{] **U4** fn=`counts`
  > let t = unsafe { &*TABLE.0.get() }; let e = t.slots[usize::from(vector) - VEC_FIRST].as_ref(); Ok(( 
- `kernel/src/irq.rs:254` [{] **U4** fn=`checked`
  > let t = unsafe { &*TABLE.0.get() }; let i = h.slot as usize; if i >= SLOTS { 
- `kernel/src/irq.rs:288` [{] **U4** fn=`dispatch`
  > let ran = unsafe { let t = &*TABLE.0.get(); match t.slots[vector - VEC_FIRST].as_ref() { 

### ktest

- `kernel/src/ktest.rs:56` [{] **U6** fn=`run_all`
  > let tests = unsafe { core::slice::from_raw_parts(start as *const KTest, bytes / size) };  let mut passed = 0usize; 

### ktests/acpi

- `kernel/src/ktests/acpi.rs:33` [{] **U6** fn=`t_rsdp_signature_at_virtual_addr`
  > let got = unsafe { core::ptr::read_volatile((raw as *const u8).add(i)) }; if got != SIG[i] { crate::log_fatal!("rsdp signature mismatch at byte {}: got {:#02x} want {:#02x}", i, got, SIG[i]); 

### ktests/crash

- `kernel/src/ktests/crash.rs:232` [{] **U6** fn=`t_crash_oops`
  > let v = unsafe { (BAD as *const u64).read_volatile() }; crate::log_fatal!("oops: 没有发生故障，读到 {:#x} ⇒ 这条构建没在量它声称的东西", v); false 

### ktests/elf

- `kernel/src/ktests/elf.rs:21` [impl] **U4** fn=`—`
  > unsafe impl Sync for ElfScratch {} static ELF_BUF: ElfScratch = ElfScratch(UnsafeCell::new([0u8; ELF_SCRATCH]));  
- `kernel/src/ktests/elf.rs:34` [{] **U4** fn=`with_elf_copy`
  > let buf = unsafe { &mut *ELF_BUF.0.get() }; buf[..n].copy_from_slice(HELLO_ELF); Some(f(&mut buf[..n])) 

### ktests/fs

- `kernel/src/ktests/fs.rs:546` [impl] **U4** fn=`t_fat32_mem`
  > unsafe impl Sync for ElfDiskScratch {} #[cfg(feature = "fat32-exec")] static ELF_DISK: ElfDiskScratch = ElfDiskScratch(UnsafeCell::new([0u8; ELF_DISK_MAX])); 
- `kernel/src/ktests/fs.rs:633` [{] **U6** fn=`t_fat32_exec`
  > unsafe { let buf = &mut *dst; buf[fed..fed + chunk.len()].copy_from_slice(chunk); 
- `kernel/src/ktests/fs.rs:643` [{] **U6** fn=`t_fat32_exec`
  > let head = unsafe { (*dst).as_ptr() }; (w, unsafe { core::slice::from_raw_parts(head, size) }) } 
- `kernel/src/ktests/fs.rs:644` [{] **U6** fn=`t_fat32_exec`
  > (w, unsafe { core::slice::from_raw_parts(head, size) }) } Err(e) => { 

### ktests/heap

- `kernel/src/ktests/heap.rs:43` [{] **U6** fn=`t_heap_reuses_freed_slot`
  > unsafe { core::ptr::write_bytes(p, 0x5a, 100) }; // SAFETY: 同一槽位归还 unsafe { 
- `kernel/src/ktests/heap.rs:45` [{] **U6** fn=`t_heap_reuses_freed_slot`
  > unsafe { if !heap::dealloc_small(p, 100) { return false; 
- `kernel/src/ktests/heap.rs:102` [{] **U6** fn=`t_heap_slots_are_mapped`
  > unsafe { core::ptr::write_volatile(p, 0x4c); core::ptr::write_volatile(p.add(cls - 1), 0x7a); 
- `kernel/src/ktests/heap.rs:107` [{] **U6** fn=`t_heap_slots_are_mapped`
  > let head_ok = unsafe { core::ptr::read_volatile(p) } == 0x4c; let tail_ok = unsafe { core::ptr::read_volatile(p.add(cls - 1)) } == 0x7a; if !(head_ok && tail_ok) { 
- `kernel/src/ktests/heap.rs:108` [{] **U6** fn=`t_heap_slots_are_mapped`
  > let tail_ok = unsafe { core::ptr::read_volatile(p.add(cls - 1)) } == 0x7a; if !(head_ok && tail_ok) { crate::log_fatal!("heap slot {:#x} read-back wrong", p as usize); 
- `kernel/src/ktests/heap.rs:122` [{] **U6** fn=`t_heap_slots_are_mapped`
  > unsafe { if !heap::dealloc_small(p, cls) { return false; 

### ktests/mm

- `kernel/src/ktests/mm.rs:26` [{] **U6** fn=`t_alloc_free_returns_frames`
  > let v = unsafe { core::ptr::read_volatile(p as *const u8) }; v == 0xa5 }; 
- `kernel/src/ktests/mm.rs:59` [{] **U6** fn=`t_map_write_unmap`
  > unsafe { core::ptr::write_volatile(m.virt().0 as *mut u64, MAGIC) }; // SAFETY: 同上 let got = unsafe { core::ptr::read_volatile(m.virt().0 as *mut u64) }; 
- `kernel/src/ktests/mm.rs:61` [{] **U6** fn=`t_map_write_unmap`
  > let got = unsafe { core::ptr::read_volatile(m.virt().0 as *mut u64) }; let mapped_before = mm::is_mapped(m.virt().0); let after_alloc = mm::free_frames(); 

### ktests/sched

- `kernel/src/ktests/sched.rs:377` [{] **U6** fn=`t_if_patch_both_branches`
  > unsafe { core::ptr::addr_of!((*f.as_ptr()).rflags) as u64 - base } }; let size_ok = core::mem::size_of::<trap::TrapFrame>() == 23 * 8; 
- `kernel/src/ktests/sched.rs:387` [{] **U1** fn=`t_if_patch_both_branches`
  > unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) }; let opened = words[20]; // SAFETY: 同上 
- `kernel/src/ktests/sched.rs:390` [{] **U1** fn=`t_if_patch_both_branches`
  > unsafe { sched::if_patch(words.as_mut_ptr() as u64, 0) }; let closed = words[20]; // 另外还要确认"置位"这条分支幂等，且不会顺手清掉别的位 
- `kernel/src/ktests/sched.rs:395` [{] **U1** fn=`t_if_patch_both_branches`
  > unsafe { sched::if_patch(words.as_mut_ptr() as u64, 1) }; let idempotent = words[20]; let untouched = words 
- `kernel/src/ktests/sched.rs:572` [{] **U6** fn=`t_tlb_shootdown`
  > unsafe { core::ptr::write_volatile(win.0 as *mut u64, 0x5a5a_5a5a_5a5a_5a5a) }; let written = unsafe { core::ptr::read_volatile(win.0 as *const u64) }; drop(m); 
- `kernel/src/ktests/sched.rs:573` [{] **U6** fn=`t_tlb_shootdown`
  > let written = unsafe { core::ptr::read_volatile(win.0 as *const u64) }; drop(m); let after = mm::shootdown_stats(); 

### ktests/sign

- `kernel/src/ktests/sign.rs:84` [impl] **U4** fn=`t_sha256`
  > unsafe impl Sync for PkgScratch {} #[cfg(feature = "sig-check")] static PKG_BUF: PkgScratch = PkgScratch(UnsafeCell::new([0u8; sign::PKG_BYTES])); 
- `kernel/src/ktests/sign.rs:109` [{] **U4** fn=`t_sig_package`
  > let buf = unsafe { &mut *PKG_BUF.0.get() }; let mut off = 0usize; let mut reads = 0usize; 

### ktests/user

- `kernel/src/ktests/user.rs:141` [{] **U6** fn=`t_user_roundtrip`
  > let w = unsafe { [ core::ptr::read_volatile(f as *const u64), 

### limine

- `kernel/src/limine.rs:116` [fn] **U2** fn=`response`
  > unsafe fn response<T>(p: &AtomicPtr<T>) -> Option<&T> { // SAFETY: 由本函数的调用约定保证（见函数文档） unsafe { p.load(Ordering::Relaxed).cast_const().as_ref() } 
- `kernel/src/limine.rs:118` [{] **U2** fn=`response`
  > unsafe { p.load(Ordering::Relaxed).cast_const().as_ref() } }  
- `kernel/src/limine.rs:139` [{] **U2** fn=`response`
  > unsafe { response(&self.response) } } } 
- `kernel/src/limine.rs:230` [{] **U2** fn=`response`
  > unsafe { response(&self.response) } } } 
- `kernel/src/limine.rs:276` [fn] **U3** fn=`release_mp_cpu`
  > pub unsafe fn release_mp_cpu(p: *mut MpInfo, extra_argument: u64, entry: u64) { // SAFETY: 见函数文档。extra_argument 是普通 u64 字段，用 volatile 写保证它 // 一定落在发布之前（编译器不能把它和下面的原子写对调）。 
- `kernel/src/limine.rs:279` [{] **U3** fn=`release_mp_cpu`
  > unsafe { core::ptr::write_volatile(&raw mut (*p).extra_argument, extra_argument) }; // goto_address 是 AtomicU64：借一个 & 出来做 store，语义就是协议要的那次发布 // SAFETY: 见函数文档 
- `kernel/src/limine.rs:282` [{] **U3** fn=`release_mp_cpu`
  > unsafe { &*(&raw const (*p).goto_address as *const core::sync::atomic::AtomicU64) } .store(entry, Ordering::Release); } 
- `kernel/src/limine.rs:305` [{] **U2** fn=`read_mp`
  > let info = unsafe { resp.cpus.add(i).read() }; if info.is_null() { m.all_goto_null = false; 
- `kernel/src/limine.rs:311` [{] **U3** fn=`read_mp`
  > let info = unsafe { &*info }; if info.goto_address.load(Ordering::Acquire) != 0 { m.all_goto_null = false; 
- `kernel/src/limine.rs:349` [fn] **U2** fn=`memmap_slice`
  > unsafe fn memmap_slice(resp: &MemmapResponse) -> &[*const MemmapEntry] { let base = resp.entries.load(Ordering::Relaxed).cast_const(); // SAFETY: 见函数文档 
- `kernel/src/limine.rs:352` [{] **U2** fn=`memmap_slice`
  > unsafe { core::slice::from_raw_parts(base, resp.entry_count as usize) } }  
- `kernel/src/limine.rs:377` [{] **U2** fn=`collect`
  > let byte = unsafe { p.add(n).read_volatile() }; if byte == 0 || !(0x20..0x7f).contains(&byte) { break; 
- `kernel/src/limine.rs:387` [{] **U2** fn=`collect`
  > core::str::from_utf8(unsafe { core::slice::from_raw_parts(p, n) }).ok() } }); 
- `kernel/src/limine.rs:391` [{] **U2** fn=`collect`
  > let mmap_entries = unsafe { memmap_slice(memmap) }; Some(BootInfo { hhdm_offset: hhdm.offset, mmap_entries, rsdp, bootloader_name, mp }) } 

### main

- `kernel/src/main.rs:71` [impl] **U4** fn=`—`
  > unsafe impl Sync for MpCell {} static MP_SNAP: MpCell = MpCell(UnsafeCell::new(MpSlot(None)));  
- `kernel/src/main.rs:77` [{] **U4** fn=`mp_store`
  > unsafe { (*MP_SNAP.0.get()) = MpSlot(Some(m)) }; }  
- `kernel/src/main.rs:82` [{] **U4** fn=`mp_snapshot`
  > unsafe { (*MP_SNAP.0.get()).0 } }  

### mm

- `kernel/src/mm.rs:279` [impl] **U4** fn=`—`
  > unsafe impl Sync for StateCell {}  static S: StateCell = StateCell(UnsafeCell::new(State { 
- `kernel/src/mm.rs:307` [impl] **U4** fn=`—`
  > unsafe impl Sync for RegionsCell {}  static REGIONS: RegionsCell = RegionsCell(UnsafeCell::new( 
- `kernel/src/mm.rs:316` [{] **U4** fn=`regs`
  > unsafe { &mut *REGIONS.0.get() } }  
- `kernel/src/mm.rs:325` [{] **U4** fn=`s`
  > unsafe { &mut *S.0.get() } }  
- `kernel/src/mm.rs:738` [{] **U2** fn=`take_over`
  > let e = unsafe { &*p }; if n >= MAX_REGIONS { return Err(MmError::Unsupported); 
- `kernel/src/mm.rs:775` [{] **U2** fn=`take_over`
  > let img_lo = (unsafe { &raw const __text_start } as u64) & !(PAGE as u64 - 1); let split = align_up(unsafe { &raw const __rodata_end } as u64, PAGE as u64); let data_lo = (unsafe { &raw const __data_start } as u64) & !(PAGE as u64 - 1); 
- `kernel/src/mm.rs:776` [{] **U2** fn=`take_over`
  > let split = align_up(unsafe { &raw const __rodata_end } as u64, PAGE as u64); let data_lo = (unsafe { &raw const __data_start } as u64) & !(PAGE as u64 - 1); let img_hi = align_up(unsafe { &raw const __bss_end } as u64, PAGE as u64); 
- `kernel/src/mm.rs:777` [{] **U2** fn=`take_over`
  > let data_lo = (unsafe { &raw const __data_start } as u64) & !(PAGE as u64 - 1); let img_hi = align_up(unsafe { &raw const __bss_end } as u64, PAGE as u64); let image_phys = exec_region_phys_base().ok_or(MmError::InvalidAddress)?; 
- `kernel/src/mm.rs:778` [{] **U2** fn=`take_over`
  > let img_hi = align_up(unsafe { &raw const __bss_end } as u64, PAGE as u64); let image_phys = exec_region_phys_base().ok_or(MmError::InvalidAddress)?; st.img_va_lo = img_lo; 
- `kernel/src/mm.rs:815` [{] **U1** fn=`take_over`
  > unsafe { core::arch::asm!( "call mm_relocate", 
- `kernel/src/mm.rs:912` [{] **U2** fn=`new_table_frame`
  > unsafe { core::ptr::write_bytes((phys + st.hhdm) as *mut u8, 0, PAGE) }; Some(phys) } 
- `kernel/src/mm.rs:922` [fn] **U2** fn=`walk_leaf`
  > unsafe fn walk_leaf(va: u64, create: bool, huge: bool, user: bool) -> Option<*mut u64> { let hhdm = s().hhdm; let mut table = (s().pml4_phys + hhdm) as *mut Page; 
- `kernel/src/mm.rs:930` [{] **U2** fn=`walk_leaf`
  > let entry = unsafe { &mut (*table).0[idx(va, level)] as *mut u64 }; if level == stop { return Some(entry); 
- `kernel/src/mm.rs:935` [{] **U2** fn=`walk_leaf`
  > let cur = unsafe { *entry }; if cur & P_PRESENT == 0 { if !create { 
- `kernel/src/mm.rs:941` [{] **U2** fn=`walk_leaf`
  > unsafe { *entry = new_table_frame()? | P_PRESENT | P_WRITE | share }; } else if cur & P_HUGE != 0 { // 还要继续下钻，但这一级已经是 2 MiB 大页：**拒绝**。 
- `kernel/src/mm.rs:951` [{] **U2** fn=`walk_leaf`
  > unsafe { *entry = cur | P_USER }; } // SAFETY: 表项里的物理地址经 HHDM 可达 
- `kernel/src/mm.rs:954` [{] **U2** fn=`walk_leaf`
  > table = unsafe { ((*entry & ADDR_MASK) + hhdm) as *mut Page }; level -= 1; } 
- `kernel/src/mm.rs:962` [{] **U2** fn=`set_leaf`
  > let e = unsafe { walk_leaf(va, true, huge, user).ok_or(MmError::OutOfMemory)? }; // SAFETY: 上一步返回的是有效表项指针 if unsafe { *e } & P_PRESENT != 0 { 
- `kernel/src/mm.rs:964` [{] **U2** fn=`set_leaf`
  > if unsafe { *e } & P_PRESENT != 0 { return Err(MmError::AlreadyMapped); } 
- `kernel/src/mm.rs:968` [{] **U2** fn=`set_leaf`
  > unsafe { *e = value }; Ok(()) } 
- `kernel/src/mm.rs:983` [{] **U2** fn=`huge_block_of`
  > unsafe { let mut table = (st.pml4_phys + hhdm) as *const Page; for level in (1u8..=3u8).rev() { 
- `kernel/src/mm.rs:1241` [{] **U1** fn=`tlb_invalidate`
  > unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nomem)) }; core::sync::atomic::compiler_fence(Ordering::SeqCst); } 
- `kernel/src/mm.rs:1247` [{] **U2** fn=`clear_leaf`
  > if let Some(e) = unsafe { walk_leaf(va.0, false, false, false) } { // SAFETY: walk_leaf 只返回有效表项 unsafe { *e = 0 }; 
- `kernel/src/mm.rs:1249` [{] **U2** fn=`clear_leaf`
  > unsafe { *e = 0 }; tlb_invalidate(va.0); } 
- `kernel/src/mm.rs:1275` [{] **U2** fn=`is_mapped`
  > unsafe { let mut table = (s().pml4_phys + hhdm) as *const Page; let mut level = 3u8; 
- `kernel/src/mm.rs:1311` [{] **U2** fn=`effective_flags`
  > unsafe { let mut table = (s().pml4_phys + hhdm) as *const Page; let mut level = 3u8; 
- `kernel/src/mm.rs:1479` [{] **U2** fn=`phys_free`
  > unsafe { core::ptr::write_volatile((st.hhdm + base.0 + b) as *mut u8, 0xa5) }; } if !crate::resource::account_free(owner, n) { 

### pci

- `kernel/src/pci.rs:51` [impl] **U4** fn=`—`
  > unsafe impl Sync for TableCell {} static TABLE: TableCell = TableCell(UnsafeCell::new(None));  
- `kernel/src/pci.rs:58` [impl] **U4** fn=`—`
  > unsafe impl Sync for EcamCell {} static ECAM: EcamCell = EcamCell(UnsafeCell::new(None));  
- `kernel/src/pci.rs:66` [{] **U4** fn=`ecam_va`
  > unsafe { (*ECAM.0.get()).as_ref().map(|r| r.base()) } }  
- `kernel/src/pci.rs:78` [{] **U2** fn=`cfg_read32`
  > unsafe { core::ptr::read_volatile((va + o) as *const u32) } } None => { 
- `kernel/src/pci.rs:97` [{] **U2** fn=`cfg_write32`
  > unsafe { core::ptr::write_volatile((va + o) as *mut u32, v) } } None => { 
- `kernel/src/pci.rs:108` [{] **U4** fn=`info`
  > unsafe { (*TABLE.0.get()).as_ref().map(|(i, _)| *i) } }  
- `kernel/src/pci.rs:113` [{] **U4** fn=`dev`
  > unsafe { (*TABLE.0.get()) .as_ref() 
- `kernel/src/pci.rs:168` [{] **U4** fn=`init`
  > unsafe { *ECAM.0.get() = Some(r) }; backend = Backend::Ecam; crate::log_info!("pci: ECAM pa={:#x} va={:#x} span={} MiB", pa, va, span); 
- `kernel/src/pci.rs:203` [{] **U4** fn=`init`
  > unsafe { *TABLE.0.get() = Some((info, out)) }; info } 
- `kernel/src/pci.rs:214` [{] **U2** fn=`ecam_class`
  > unsafe { core::ptr::read_volatile((va + o) as *const u32) } } None => 0, 

### sched
- `kernel/src/sched.rs:346` [impl] **U4** fn=`reap`
  > unsafe impl Sync for QueueCell {} static RQ: [QueueCell; crate::arch::x86_64::cpu::MAX_CPUS] = [const { QueueCell { lock: crate::sync::IrqSpinLock::new(crate::sync::RANK_RUNQ, ()), data: core::cell::UnsafeCell::new(EMPTY_QUEUE) }
- `kernel/src/sched.rs:367` [{] **U4** fn=`reap`
  > unsafe { &*self.cell.data.get() } } }
- `kernel/src/sched.rs:374` [{] **U4** fn=`reap`
  > unsafe { &mut *self.cell.data.get() } } }
- `kernel/src/sched.rs:560` [{] **U4** fn=`current_of`
  > unsafe { (*RQ[cpu].data.get()).current } } 
- `kernel/src/sched.rs:646` [{] **U1** fn=`yield_now`
  > unsafe { core::arch::asm!("int {}", const crate::arch::x86_64::trap::VEC_RESCHED) }; } 
- `kernel/src/sched.rs:691` [{] **U2** fn=`frame_rflags_of`
  > Some(unsafe { core::ptr::read_volatile((f as usize + RFLAGS_OFF) as *const u64) }) } 
- `kernel/src/sched.rs:701` [{] **U4** fn=`owned_of`
  > unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].owned.count() } } 
- `kernel/src/sched.rs:712` [{] **U4** fn=`task_frame`
  > Some(unsafe { (*RQ[cpu_of(task)].data.get()).tasks[slot_of(task)].frame }) } 
- `kernel/src/sched.rs:785` [impl] **U4** fn=`init_idle_task`
  > unsafe impl Sync for IdleStackCell {} static IDLE_STACKS: [IdleStackCell; crate::arch::x86_64::cpu::MAX_CPUS] = [const { IdleStackCell(core::cell::UnsafeCell::new(IdleStack([0; IDLE_STACK_BYTES]))) };
- `kernel/src/sched.rs:838` [{] **U2** fn=`init_idle`
  > unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) }; } let gi = gidx(cpu, slot);
- `kernel/src/sched.rs:898` [{] **U2** fn=`spawn`
  > unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) }; } s.entries[slot] = Some(entry);
- `kernel/src/sched.rs:952` [{] **U2** fn=`spawn_user`
  > unsafe { core::ptr::write_volatile((f + i * 8) as *mut u64, *v) }; } s.entries[slot] = None; // 用户任务没有内核入口函数
- `kernel/src/sched.rs:1061` [{] **U4** fn=`on_cpu_of`
  > Some(unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].on_cpu as usize }) } 
- `kernel/src/sched.rs:1070` [{] **U4** fn=`stack_bounds`
  > let t = unsafe { &(*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)] }; if t.stack_lo == 0 { return None;
- `kernel/src/sched.rs:1087` [{] **U4** fn=`kstack_top_of`
  > let t = unsafe { &(*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)] }; if t.kstack_hi == 0 { return None;
- `kernel/src/sched.rs:1099` [{] **U4** fn=`state_of`
  > unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].state } } 
- `kernel/src/sched.rs:1109` [{] **U4** fn=`is_user`
  > unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].user } } 
- `kernel/src/sched.rs:1117` [{] **U4** fn=`runs_of`
  > unsafe { (*RQ[cpu_of(i)].data.get()).tasks[slot_of(i)].runs } } 
- `kernel/src/sched.rs:1156` [fn] **U2** fn=`preempt_point`
  > pub unsafe fn preempt_point(frame: u64, cpu: usize) { // 不跑调度器的 CPU 直接把标志倒掉再返回。今天 AP 的中断根本不经过这里 // （`isr_stub_cpu_timer` 是独立快路径），这条判断是给"把 AP 接进调度"留的
- `kernel/src/sched.rs:1244` [{] **U1** fn=`preempt_point`
  > unsafe { p1_extra_flush(frame) }; crate::tsc::spin(20_000); }
- `kernel/src/sched.rs:1268` [{] **U1** fn=`preempt_point`
  > unsafe { context_load(resume, if_open as u64) } } 
- `kernel/src/sched.rs:1296` [{] **U2** fn=`preempt_hook`
  > unsafe { preempt_point(frame, cpu) } }
### serial

- `kernel/src/serial.rs:23` [{] **U1** fn=`out8`
  > unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) } }  
- `kernel/src/serial.rs:30` [{] **U1** fn=`in8`
  > unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) }; v } 

### sync

- `kernel/src/sync.rs:62` [impl] **U4** fn=`—`
  > unsafe impl<T: Send> Sync for IrqSpinLock<T> {}  #[must_use = "丢弃守卫会立即释放锁，等于什么都没锁（§7.1 R16）"] 
- `kernel/src/sync.rs:84` [{] **U4** fn=`—`
  > unsafe { &mut *self.lock.data.get() } } } 
- `kernel/src/sync.rs:95` [{] **U4** fn=`—`
  > unsafe { self.lock.locked.store(0, Ordering::Release) }; restore_flags(self.flags); } 
- `kernel/src/sync.rs:106` [{] **U1** fn=`save_and_cli`
  > unsafe { core::arch::asm!( "pushfq", 
- `kernel/src/sync.rs:120` [{] **U1** fn=`restore_flags`
  > unsafe { core::arch::asm!("push {r}", "popfq", r = in(reg) f) }; }  

### tsc

- `kernel/src/tsc.rs:31` [{] **U1** fn=`now`
  > unsafe { core::arch::asm!( "rdtsc", 

### user

- `kernel/src/user.rs:294` [impl] **U4** fn=`sys_file_read`
  > unsafe impl Sync for ProgCell {} static PROG_PTR: ProgCell = ProgCell(core::cell::UnsafeCell::new(None));  
- `kernel/src/user.rs:368` [{] **U2** fn=`ensure_trampoline`
  > unsafe { core::ptr::write_bytes(f.base().via_hhdm().0 as *mut u8, 0, mm::PAGE); core::ptr::write_volatile( 
- `kernel/src/user.rs:458` [{] **U4** fn=`init`
  > return Ok(unsafe { (*PROG_PTR.0.get()).as_ref().unwrap() }); } // 先有落脚页，再建用户任务：`init` 建的镜像不再是 kill 的前提，但它自己也要有 
- `kernel/src/user.rs:482` [{] **U2** fn=`init`
  > unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), cf.base().via_hhdm().0 as *mut u8, bytes.len()); // 三个槽先填"没写过"的哨兵，用例才能区分"用户真写了"与"页本来就是 0" 
- `kernel/src/user.rs:511` [{] **U4** fn=`init`
  > unsafe { *PROG_PTR.0.get() = Some(p); PROG.store(1, Ordering::Release); 
- `kernel/src/user.rs:520` [{] **U4** fn=`init`
  > Ok(unsafe { (*PROG_PTR.0.get()).as_ref().unwrap() }) }  
- `kernel/src/user.rs:569` [{] **U4** fn=`prog`
  > unsafe { (*PROG_PTR.0.get()).as_ref() } }  
- `kernel/src/user.rs:779` [impl] **U4** fn=`ptr_err_to_ret`
  > unsafe impl Sync for Scratch {} static SCRATCH: Scratch = Scratch(core::cell::UnsafeCell::new([0u8; COPY_MAX]));  
- `kernel/src/user.rs:825` [{] **U5** fn=`copy_from_user`
  > let got = unsafe { ucopy_from(dst.as_mut_ptr().add(done), at as *const u8, want) }; done += got; if got < want { 
- `kernel/src/user.rs:848` [{] **U5** fn=`copy_to_user`
  > let got = unsafe { ucopy_to(at as *mut u8, src.as_ptr().add(done), want) }; done += got; if got < want { 
- `kernel/src/user.rs:875` [{] **U4** fn=`poke_pattern_into`
  > let buf = unsafe { &mut *SCRATCH.0.get() }; for (j, b) in buf[..len].iter_mut().enumerate() { *b = poke_pattern(j); 
- `kernel/src/user.rs:884` [{] **U5** fn=`poke_pattern_into`
  > let got = unsafe { ucopy_to(at as *mut u8, buf.as_ptr().add(done), want) }; done += got; if got < want { 
- `kernel/src/user.rs:920` [{] **U4** fn=`copy_into_scratch`
  > let buf = unsafe { &mut *SCRATCH.0.get() }; let mut done = 0usize; while done < len { 
- `kernel/src/user.rs:926` [{] **U5** fn=`copy_into_scratch`
  > let got = unsafe { ucopy_from(buf.as_mut_ptr().add(done), at as *const u8, want) }; done += got; if got < want { 
- `kernel/src/user.rs:947` [{] **U5** fn=`probe_copy_from`
  > let buf = unsafe { &mut *SCRATCH.0.get() }; unsafe { ucopy_from(buf.as_mut_ptr(), va as *const u8, len) } }) 
- `kernel/src/user.rs:948` [{] **U5** fn=`probe_copy_from`
  > unsafe { ucopy_from(buf.as_mut_ptr(), va as *const u8, len) } }) } 
- `kernel/src/user.rs:974` [{] **U1** fn=`ac_active`
  > unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) f, options(nomem, preserves_flags)) }; f & (1 << 18) != 0 } 
- `kernel/src/user.rs:1099` [{] **U2** fn=`load`
  > unsafe { core::ptr::write_bytes(fill as *mut u8, 0, mm::PAGE) }; if copy > 0 { let at = seg.offset + page_in_seg * mm::PAGE as u64; 
- `kernel/src/user.rs:1107` [{] **U2** fn=`load`
  > unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), fill as *mut u8, copy) }; } } 
- `kernel/src/user.rs:1129` [{] **U2** fn=`load`
  > unsafe { core::ptr::write_volatile(sf.base().via_hhdm().0 as *mut u64, 0) }; let m = mm::map(VirtAddr(stack_va), sf, PageFlags::USER_RW).map_err(LoadError::Mm)?; owned.push(m).map_err(LoadError::Mm)?; 

### user/hello

- `user/hello/src/main.rs:115` [{] **U1** fn=`stack_base`
  > unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) }; rsp & !0xfff } 
- `user/hello/src/main.rs:148` [{] **U1** fn=`panic`
  > unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } } 
- `user/hello/src/main.rs:265` [fn] **U1** fn=`syscall_fast`
  > unsafe fn syscall_fast(nr: u64, a1: u64, a2: u64) -> u64 { let ret: u64; let mut c0: u64; 
- `user/hello/src/main.rs:270` [{] **U1** fn=`syscall_fast`
  > unsafe { core::arch::asm!( "syscall", 
- `user/hello/src/main.rs:291` [{] **U1** fn=`self_cs`
  > unsafe { core::arch::asm!("mov {}, cs", out(reg) v, options(nomem, nostack, preserves_flags)) }; v as u64 } 
- `user/hello/src/main.rs:299` [{] **U1** fn=`self_ss`
  > unsafe { core::arch::asm!("mov {}, ss", out(reg) v, options(nomem, nostack, preserves_flags)) }; v as u64 } 
- `user/hello/src/main.rs:309` [fn] **U1** fn=`syscall`
  > unsafe fn syscall(nr: u64, a1: u64, a2: u64) -> u64 { let ret: u64; // SAFETY: 见上。`preserves_flags` 是对的：中断门在内核侧清掉的是**内核**的 IF， 
- `user/hello/src/main.rs:313` [{] **U1** fn=`syscall`
  > unsafe { core::arch::asm!( "int 0x80", 
- `user/hello/src/main.rs:337` [fn] **U1** fn=`syscall3`
  > unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 { let ret: u64; // SAFETY: 同 `syscall`；rdx 只是第三个参数。 
- `user/hello/src/main.rs:340` [{] **U1** fn=`syscall3`
  > unsafe { core::arch::asm!( "int 0x80", 
- `user/hello/src/main.rs:359` [{] **U5** fn=`_start`
  > let n = unsafe { syscall(SYS_PING, 0, 0) }; SLOTS.ping.store(n, Ordering::Relaxed); // **P7 归因的换位实验**（第一次归因给出 lead=[87193, 25898, 23762, 371]： 
- `user/hello/src/main.rs:368` [{] **U5** fn=`_start`
  > let _ = unsafe { syscall(SYS_PING, 1, 0) }; // 2) 参数确实穿过边界：0x2a + 0x12 = 0x3c let sum = unsafe { syscall(SYS_ADD, 0x2a, 0x12) }; 
- `user/hello/src/main.rs:370` [{] **U5** fn=`_start`
  > let sum = unsafe { syscall(SYS_ADD, 0x2a, 0x12) }; SLOTS.add.store(sum, Ordering::Relaxed); // 3) 没人认领的号必须回 -1（错误码），而不是把系统调用打挂 
- `user/hello/src/main.rs:373` [{] **U5** fn=`_start`
  > let bad = unsafe { syscall(SYS_NOBODY, 0, 0) }; SLOTS.unknown.store(bad, Ordering::Relaxed); // 读一次 .rodata 再写进第四个槽：这条动作同时证明"那段装了、且 ring3 读得到" 
- `user/hello/src/main.rs:382` [{] **U5** fn=`_start`
  > let _ = unsafe { syscall(SYS_PING, n, 0) }; n += 1; } 
- `user/hello/src/main.rs:401` [{] **U5** fn=`_start`
  > let good = unsafe { syscall(SYS_PEEK, core::ptr::addr_of!(probe) as u64, 0) }; SLOTS.peek_ok.store(good, Ordering::Relaxed); // `probe` 被取过地址，不能被优化掉；这里再读一次，明确它还在。 
- `user/hello/src/main.rs:404` [{] **U5** fn=`_start`
  > if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(probe)) } == 0 { SLOTS.peek_ok.store(0, Ordering::Relaxed); } 
- `user/hello/src/main.rs:407` [{] **U5** fn=`_start`
  > let kern = unsafe { syscall(SYS_PEEK, 0xffff_ffff_8000_0000, 0) }; SLOTS.peek_kernel.store(kern, Ordering::Relaxed); // 自己栈页下面那一页的末尾 8 字节：那一页**永不映射**（`mm::alloc_user_va_range(2)` 
- `user/hello/src/main.rs:413` [{] **U5** fn=`_start`
  > let unmapped = unsafe { syscall(SYS_PEEK, guard, 0) }; SLOTS.peek_unmapped.store(unmapped, Ordering::Relaxed); } 
- `user/hello/src/main.rs:425` [{] **U5** fn=`_start`
  > let n = unsafe { syscall(SYS_POKE_BUF, ptr, BUF_LEN) }; SLOTS.buf_n.store(n, Ordering::Relaxed); let mut ok: u64 = 1; 
- `user/hello/src/main.rs:431` [{] **U5** fn=`_start`
  > let v = unsafe { core::ptr::read_volatile((ptr + j) as *const u8) }; if v != poke_pattern(j) { ok = 0x1000 + j; 
- `user/hello/src/main.rs:448` [{] **U5** fn=`_start`
  > unsafe { core::ptr::write_volatile((ptr + j) as *mut u8, write_pattern(j)) }; j += 1; } 
- `user/hello/src/main.rs:451` [{] **U5** fn=`_start`
  > let sum = unsafe { syscall(SYS_PEEK_BUF, ptr, BUF_LEN) }; SLOTS.buf_sum.store(sum, Ordering::Relaxed); // 3) 故意要一个**超限**的长度：内核必须回 `-3`（`-ETOOLONG`）， 
- `user/hello/src/main.rs:457` [{] **U5** fn=`_start`
  > let err = unsafe { syscall(SYS_PEEK_BUF, ptr, COPY_MAX + 1) }; SLOTS.buf_err.store(err, Ordering::Relaxed); } 
- `user/hello/src/main.rs:463` [{] **U5** fn=`_start`
  > let word = unsafe { syscall(SYS_ABI_INFO, 0, 0) }; SLOTS.abi_word.store(word, Ordering::Relaxed); if word & F_FASTPATH != 0 { 
- `user/hello/src/main.rs:466` [{] **U5** fn=`_start`
  > let n = unsafe { syscall_fast(SYS_PING, 0, 0) }; SLOTS.fast_ping.store(n, Ordering::Relaxed); SLOTS.fast_cs.store(self_cs(), Ordering::Relaxed); 
- `user/hello/src/main.rs:472` [{] **U5** fn=`_start`
  > let _ = unsafe { syscall_fast(SYS_PING, k, 0) }; k += 1; } 
- `user/hello/src/main.rs:485` [{] **U5** fn=`_start`
  > let n = unsafe { syscall3(SYS_FILE_READ, h, ptr, 4) }; let magic = if n == 4 { // SAFETY: `ptr` 指向本任务栈上这 4 个字节，内核刚写满 
- `user/hello/src/main.rs:488` [{] **U5** fn=`_start`
  > (unsafe { core::ptr::read_volatile(ptr as *const u32) }) as u64 } else { 0xdead_0000 | (n & 0xffff) 
- `user/hello/src/main.rs:494` [{] **U5** fn=`_start`
  > let _ = unsafe { syscall(SYS_HANDLE_CLOSE, h, 0) }; // 最后一个写：内核等这一格非 0 才读上面三格 SLOTS.h_done.store(HANDLE_DONE, Ordering::Relaxed); 
- `user/hello/src/main.rs:504` [{] **U5** fn=`_start`
  > unsafe { core::ptr::write_volatile(p, 0xdead) }; // 写成功了 = 隔离没生效。这里不猜结论：把"居然成功了"这件事写回槽位， // 由内核侧的判据去红（红得有数字，而不是靠有没有走到下一行）。 
- `user/hello/src/main.rs:510` [{] **U5** fn=`_start`
  > let _ = unsafe { syscall(SYS_EXIT, 0, 0) }; // 正常不会回到这里：内核标了 Free 并把 CPU 换给别人了。 // 万一回来了（退出请求被吞掉），就停在自跳转里，等旁观者 `terminate_task` 收—— 
- `user/hello/src/main.rs:516` [{] **U1** fn=`_start`
  > unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } } 
- `user/hello/src/main.rs:525` [{] **U1** fn=`_start`
  > unsafe { core::arch::asm!("2: jmp 2b", options(nomem, nostack, noreturn)) }; } } 

### virtio

- `kernel/src/virtio.rs:455` [impl] **U4** fn=`off_in`
  > unsafe impl Sync for DevCell {} static DEV: DevCell = DevCell(core::cell::UnsafeCell::new(None));  
- `kernel/src/virtio.rs:463` [{] **U4** fn=`b`
  > unsafe { (*DEV.0.get()).as_ref().map(f).ok_or(VirtioError::NoDevice)? } }  
- `kernel/src/virtio.rs:565` [{] **U4** fn=`bind`
  > if unsafe { (*DEV.0.get()).is_some() } { return Ok(()); } 
- `kernel/src/virtio.rs:602` [{] **U4** fn=`bind`
  > unsafe { *DEV.0.get() = Some(bound) }; Ok(()) } 
- `kernel/src/virtio.rs:609` [{] **U4** fn=`status`
  > unsafe { (*DEV.0.get()).as_ref().map(|d| { ( 
- `kernel/src/virtio.rs:865` [impl] **U4** fn=`net_payload_byte`
  > unsafe impl Sync for NetCell {} static NET_DEV: NetCell = NetCell(core::cell::UnsafeCell::new(None)); static NET_USED_SEEN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0); 
- `kernel/src/virtio.rs:871` [{] **U4** fn=`bn`
  > unsafe { (*NET_DEV.0.get()).as_ref().map(f).ok_or(VirtioError::NoDevice)? } }  
- `kernel/src/virtio.rs:877` [{] **U4** fn=`bind_net`
  > if unsafe { (*NET_DEV.0.get()).is_some() } { return Ok(()); } 
- `kernel/src/virtio.rs:976` [{] **U4** fn=`bind_net`
  > unsafe { *NET_DEV.0.get() = Some(net) }; Ok(()) } 
- `kernel/src/virtio.rs:982` [{] **U4** fn=`net_info`
  > unsafe { (*NET_DEV.0.get()).as_ref().map(|d| NetInfo { bdf: d.bdf, 
