//! 输入层：PS/2 键盘与鼠标。
//!
//! 两者共用 i8042 的 `0x60` 数据口，靠状态位 bit5 分流（键盘只吃 bit5=0 的字节）。
//! 这条分流不是可选项：`mouse.rs` 的注释记了实测——不分流时键盘会把鼠标包当扫描码吃掉，
//! 表现为"指针第一下能动、之后丢包"。
//!
//! 门控沿用重构前的口径：两档各自独立（`ps2-kbd` 与 `ps2-mouse` 互不蕴含）。

#[cfg(feature = "ps2-kbd")]
pub(crate) mod kbd;
#[cfg(feature = "ps2-mouse")]
pub(crate) mod mouse;
