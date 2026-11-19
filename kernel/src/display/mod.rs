//! 显示层：帧缓冲窗口与文本→像素的机制。
//!
//! 两个文件的分工是**一层不许越过另一层**：`frame` 只知道像素怎么落到显存
//! （几何、掩码、越界、双缓冲），`fbcon` 只知道字符怎么变成像素（字形资产、双宽格、
//! 浮窗、标签条）。`fbcon` 的每一次像素写入都经 `Frame::put`，自己零 `unsafe`。
//!
//! 门控沿用重构前的口径：`frame` 与 `fbcon` 都只在 `framebuffer` 档编译
//! （`fbcon-mirror` / `fbcon-live` / `ps2-mouse` / `wm` 都传递启用 `framebuffer`，
//! 所以这里的 `cfg` 与它们各自原来的 `cfg` 等价）。

#[cfg(feature = "framebuffer")]
pub(crate) mod fbcon;
#[cfg(feature = "framebuffer")]
pub(crate) mod frame;
