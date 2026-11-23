//! 显示与输入的端到端判据（ADR-170，补 AHE-04 的缺口）。
//!
//! ## 这两个域为什么以前没有端到端判据
//!
//! - **显示**：`frame.rs` 有 `draw_test_pattern()` + `samples()`，但只在
//!   `fbcon` 的启动路径里画一次，**没有用例**。判据只能靠内核自报。
//! - **输入**：`t_ps2_kbd_decode` 是**纯解码**判据（六条各对一个负样本靶子），
//!   它的注释明写「不碰端口也不碰中断，所以不需要 QMP 注入配合」。
//!   也就是说：解码对 ≠ 端口通。
//!
//! ## 这里加什么
//!
//! - `t_fb_pattern`：画测试图案，报四个采样点与整行对账的读数。
//!   **宿主机侧**（`check_fb_pattern`）从 QMP `screendump` 的 PPM 里
//!   **独立算同一份几何**，两边各自算。
//! - `t_kbd_inject`：等一次**真实按键**（由宿主机 QMP `input-send-event` 注入），
//!   报收到的字符与扫描码。宿主机按它注入的那个键对账。
//!
//! ## 为什么这两条必须靠宿主机
//!
//! 内核自报「我画了」与「显存里真的是那幅画」是两件事；
//! 内核自报「我收到了 'a'」与「宿主机真的按了 'a'」也是两件事。
//! 第二台仪器在这里不是加分项，是**唯一能证明通路真的通**的东西。

use crate::ktest;

/// 显示：画测试图案，报采样点读数。
///
/// **没有帧缓冲时明确返回 false**，不假装通过——`framebuffer` 特性没开时
/// 这条用例就该红，而不是静默跳过。
#[cfg(feature = "framebuffer")]
fn t_fb_pattern() -> bool {
    use crate::display::frame::{Frame, FrameError};

    // 用例自足（AGENTS.md）：`.ktests` 顺序由链接器决定，不假设别人已经 init 过。
    let f = match Frame::init() {
        Ok(f) => f,
        Err(FrameError::NotProvided) => {
            crate::log_fatal!("fb: 判据不成立 没有帧缓冲（启动信息没给）");
            return false;
        }
        Err(e) => {
            crate::log_fatal!("fb: 判据不成立 Frame::init 失败 {:?}", e);
            return false;
        }
    };
    if let Err(e) = f.draw_test_pattern() {
        crate::log_fatal!("fb: 判据不成立 draw_test_pattern 失败 {:?}", e);
        return false;
    }
    // 逐采样点读回（读的是**当前显存**，不是 back buffer——`put` 在非双缓冲时直写）
    let samples = f.samples();
    let mut ok_n = 0usize;
    for (name, x, y, want) in samples.iter() {
        match f.get(*x, *y) {
            Ok(got) => {
                if got == *want {
                    ok_n += 1;
                } else {
                    crate::log_warn!("fb: 采样 {} ({},{}) 是 {:#08x} 期望 {:#08x}", name, x, y, got, want);
                }
            }
            Err(e) => {
                crate::log_warn!("fb: 采样 {} ({},{}) 读不到 {:?}", name, x, y, e);
            }
        }
    }
    let all_ok = ok_n == samples.len();
    // 这一行的形状是宿主机 `check_fb_pattern` 的正则锚点，**改它要同步改那一侧**。
    crate::log_info!("fb: 判据 采样={} 全对={}", samples.len(), all_ok);
    let (w, h, pitch) = f.geom();
    crate::log_info!("fb: 几何 宽={} 高={} 步长={} bpp={}", w, h, pitch, f.masks().len());
    all_ok
}

#[cfg(not(feature = "framebuffer"))]
fn t_fb_pattern() -> bool {
    crate::log_fatal!("fb: 判据不成立 本档没开 framebuffer 特性");
    false
}

/// 输入：等一次由宿主机注入的真实按键。
///
/// **它等的是 `kbd` 的字符环**，所以证明的是「端口 → 解码 → 环」整条通。
/// `t_ps2_kbd_decode` 证的是中间那一段（解码），这一条证两端。
///
/// 窗口按**轮数**给，不按周期：周期要时钟，而时钟标定可能还没跑（§442 的教训）。
#[cfg(feature = "ps2-kbd")]
fn t_kbd_inject() -> bool {
    use crate::kbd;

    // `kbd::stats()` 是**九元组**（不是带字段的结构体）。
    // 这里只当「前后读数」用，不解读单个字段——字段顺序的权威在 `kbd.rs` 的注释里，
    // 而这条判据不需要知道它：收到字符本身就证明通路通了。
    let before = kbd::stats();
    let mut got = None;
    // 约 2 亿轮：宿主机的注入要在 `run` 起来之后才发，给足窗口。
    // 判据靠的是「收到了什么」，不是「等了多久」——超时只影响红的方式。
    for _ in 0..200_000_000u64 {
        if let Some(c) = kbd::read_char() {
            got = Some(c);
            break;
        }
        core::hint::spin_loop();
    }
    let after = kbd::stats();
    let ch = match got {
        Some(c) => c,
        None => {
            crate::log_fatal!(
                "kbd: 判据不成立 窗口内没收到按键（stats {:?} -> {:?}）",
                before, after
            );
            return false;
        }
    };
    // 宿主机注入的是 'a'（见 `tools/aurora.py` 的 KBD_INJECT_CHAR）。
    // **这一行的形状是宿主机对账的锚点**，改它要同步改那一侧。
    crate::log_info!("kbd: 判据 收到={:?} stats {:?} -> {:?}", ch, before, after);
    ch == b'a'
}

#[cfg(not(feature = "ps2-kbd"))]
fn t_kbd_inject() -> bool {
    crate::log_fatal!("kbd: 判据不成立 本档没开 ps2-kbd 特性");
    false
}

#[cfg(feature = "framebuffer")]
ktest!(KT_FB_PATTERN, t_fb_pattern);
#[cfg(feature = "ps2-kbd")]
ktest!(KT_KBD_INJECT, t_kbd_inject);

/// ADR-239：图形设备层字节部分的判据。
mod gpu;
