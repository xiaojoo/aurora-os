use crate::ktest;

/// ADR-239：**图形设备层字节部分**的证人（切片 I 第一层）。
///
/// ## 要证什么
///
/// GPU 与前面几片一样，先做**能被纯函数完整证伪**的部分：
/// `ModeInfo` 的自洽性、pitch 推导、设备识别。
///
/// ## 判据八格
///
/// 1. 合法模式 `validate` 通过；
/// 2. **`bpp=0` 报 `ZeroBpp`**（不是 `NotRgb` —— 根因优先级）；
/// 3. **`bpp` 非 8 倍数报 `BppNotByteMultiple`**（不截断）；
/// 4. **`pitch` 太小报 `PitchTooSmall`** 且带出 `need`；
/// 5. **非 RGB 报 `NotRgb`**；
/// 6. **`bochs_mode` 的 pitch 按 4 对齐**（`1280x800@32` => pitch=5120）；
/// 7. **设备识别**：四个已知 ID 各回对应 `GpuKind`，未知显示类回 `UnknownDisplay`，非显示类回 `None`；
/// 8. `fb_bytes` = `pitch * height`。
///
/// **负样本**：把 `validate` 的 `bpp == 0` 检查去掉 ⇒ 第 2 格红。
fn t_gpu_mode() -> bool {
    use crate::display::gpu::{bochs_mode, GpuKind, ModeError, ModeInfo};
    let mut ok = true;

    let good = ModeInfo { width: 1280, height: 800, pitch: 5120, bpp: 32, memory_model: 1 };

    // ① 合法
    let valid_ok = good.validate().is_ok();
    if !valid_ok {
        crate::log_fatal!("gpu: 合法模式被拒 {:?}", good.validate());
        ok = false;
    }

    // ② bpp = 0
    let zero = ModeInfo { bpp: 0, ..good };
    let zero_ok = zero.validate() == Err(ModeError::ZeroBpp);
    if !zero_ok {
        crate::log_fatal!("gpu: bpp=0 报错不对 {:?}", zero.validate());
        ok = false;
    }

    // ③ bpp 非 8 倍数
    let odd = ModeInfo { bpp: 12, ..good };
    let odd_ok = odd.validate() == Err(ModeError::BppNotByteMultiple(12));
    if !odd_ok {
        crate::log_fatal!("gpu: bpp=12 报错不对 {:?}", odd.validate());
        ok = false;
    }

    // ④ pitch 太小
    let narrow = ModeInfo { pitch: 100, ..good };
    let narrow_ok = narrow.validate() == Err(ModeError::PitchTooSmall { pitch: 100, need: 5120 });
    if !narrow_ok {
        crate::log_fatal!("gpu: pitch 太小报错不对 {:?}", narrow.validate());
        ok = false;
    }

    // ⑤ 非 RGB
    let bgr = ModeInfo { memory_model: 2, ..good };
    let bgr_ok = bgr.validate() == Err(ModeError::NotRgb(2));
    if !bgr_ok {
        crate::log_fatal!("gpu: 非 RGB 报错不对 {:?}", bgr.validate());
        ok = false;
    }

    // ⑥ bochs_mode 的 pitch 对齐
    let bm = bochs_mode(1280, 800, 32);
    let bm_ok = bm.pitch == 5120 && bm.validate().is_ok();
    // 800x600@24 => 800*3 = 2400，已 4 对齐
    let bm2 = bochs_mode(800, 600, 24);
    let bm2_ok = bm2.pitch == 2400 && bm2.validate().is_ok();
    // 801x600@24 => 2403 => 向上对齐 2404
    let bm3 = bochs_mode(801, 600, 24);
    let bm3_ok = bm3.pitch == 2404;
    if !bm_ok || !bm2_ok || !bm3_ok {
        crate::log_fatal!("gpu: bochs_mode pitch 不对 {} / {} / {}", bm.pitch, bm2.pitch, bm3.pitch);
        ok = false;
    }

    // ⑦ 设备识别
    let ids_ok = GpuKind::from_ids(0x1234, 0x1111, 0x03) == Some(GpuKind::Bochs)
        && GpuKind::from_ids(0x1013, 0x00B8, 0x03) == Some(GpuKind::Cirrus)
        && GpuKind::from_ids(0x1B36, 0x0100, 0x03) == Some(GpuKind::Qxl)
        && GpuKind::from_ids(0x1AF4, 0x1050, 0x03) == Some(GpuKind::VirtioGpu)
        && GpuKind::from_ids(0xABCD, 0x1234, 0x03) == Some(GpuKind::UnknownDisplay)
        && GpuKind::from_ids(0xABCD, 0x1234, 0x02) == None;
    if !ids_ok {
        crate::log_fatal!("gpu: 设备识别不对");
        ok = false;
    }

    // ⑧ fb_bytes
    let bytes_ok = good.fb_bytes() == Some(5120 * 800);
    if !bytes_ok {
        crate::log_fatal!("gpu: fb_bytes 不对 {:?}", good.fb_bytes());
        ok = false;
    }

    crate::log_info!(
        "gpu: 合法={} 零bpp={} 非8倍={} pitch小={} 非RGB={} bochs={} 识别={} 字节={} ⇒ {}",
        valid_ok, zero_ok, odd_ok, narrow_ok, bgr_ok, bm_ok && bm2_ok && bm3_ok, ids_ok, bytes_ok, ok
    );
    ok
}

ktest!(KT_GPU_MODE, t_gpu_mode);


/// ADR-240：**GPU 真设备探测**的证人（切片 I 第二层）。
///
/// ## 要证什么
///
/// ADR-239 是纯函数（喂 ID 回型号）。这一层**真的去读 QEMU 的显卡**。
///
/// ## 判据七格
///
/// 1. PCI 枚举里**能找到** class 0x03 的设备；
/// 2. `probe_device` 成功（ID 能读、BAR0 是内存型）；
/// 3. **识别出的型号与 vendor/device 自洽**（`from_ids` 的返回值与读数一致）；
/// 4. **BAR0 是 2 的幂且非 0**（尺寸成形状）；
/// 5. **`class == 0x03`**（显示类）；
/// 6. `probe_first` 找到的与 `probe_device` 直接调的**一致**；
/// 7. **负样本**：拿一个非显示类设备喂 `probe_device` ⇒ `NotDisplay`。
///
/// **负样本（外部）**：把 QEMU 的 `-vga none` 打开 ⇒ 第 1 格红。
fn t_gpu_probe() -> bool {
    use crate::display::gpu::{probe_device, probe_first, GpuKind, GpuProbeError};
    let mut ok = true;

    // ① 找设备
    let found = crate::display::gpu::probe_first();
    let (rd, dev) = match found {
        Some(x) => x,
        None => {
            crate::log_fatal!("gpu-probe: PCI 里没有可探测的显示设备");
            return false;
        }
    };
    let found_ok = true;

    // ②③④⑤ 读数自洽
    let kind_ok = GpuKind::from_ids(rd.vendor, rd.device, rd.class) == Some(rd.kind);
    let bar_ok = rd.bar0_len != 0 && rd.bar0_len.is_power_of_two();
    let class_ok = rd.class == 0x03;
    if !kind_ok || !bar_ok || !class_ok {
        crate::log_fatal!(
            "gpu-probe: 读数不自洽 kind={} bar_len={:#x} class={:#x}",
            kind_ok, rd.bar0_len, rd.class
        );
        ok = false;
    }

    // ⑥ probe_first 与 probe_device 一致
    let again = probe_device(&dev);
    let same_ok = again == Ok(rd);
    if !same_ok {
        crate::log_fatal!("gpu-probe: probe_first 与 probe_device 不一致");
        ok = false;
    }

    // ⑦ 负样本：非显示类设备
    let mut not_display_ok = false;
    if let Some(n) = crate::pci::info().map(|i| i.n) {
        for i in 0..n {
            if let Some(d) = crate::pci::dev(i) {
                if d.class() != 0x03 {
                    not_display_ok = probe_device(&d) == Err(GpuProbeError::NotDisplay);
                    break;
                }
            }
        }
    }
    if !not_display_ok {
        crate::log_fatal!("gpu-probe: 非显示类设备没被拒");
        ok = false;
    }

    crate::log_info!(
        "gpu-probe: 找到={} 型号={} vendor={:#06x} device={:#06x} class={:#04x}/{:#04x} bar0={:#x} len={:#x} 64={} 自洽={} 一致={} 非显示拒={} ⇒ {}",
        found_ok, rd.kind.name(), rd.vendor, rd.device, rd.class, rd.subclass,
        rd.bar0, rd.bar0_len, rd.bar0_64, kind_ok && bar_ok && class_ok, same_ok, not_display_ok, ok
    );
    ok
}

ktest!(KT_GPU_PROBE, t_gpu_probe);
