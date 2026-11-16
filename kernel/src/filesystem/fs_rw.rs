//! ADR-111：可写卷的挂载点（口 4）。
//!
//! 单独一个模块而不是塞进 `fs_open`：`fs-open` 那一档带着一整套只读判据（它们要口 5 上的多级卷），
//! 写方向不需要那些，也不该因为"想用一句 mount"就把它们一起编进来。
//! 这里只做一件事：把口 4 那块**每次现算、跑完即丢**的卷挂成单根。

use crate::filesystem::vfs::AhciDisk;
use crate::filesystem::vfs_ro::{ReadOnlyFs, VfsError};

/// 口号与 `tools/aurora.py` 的 `FS_RW_PORTS` 各写一份，由 `check-fat32-ports` 对账。
/// 为什么不是 6：q35 的 ich9-ahci 只把 ide 口 0..5 映射出来，`index=6` 直接"不支持";
/// 这一档不编 FAT 探针，口 4 空着，就用它——不新造一条没量过的挂线方式。
pub const PORT: u8 = 4;

static DISK: AhciDisk = AhciDisk { port: PORT };

/// 挂载可写卷。今天没有"挂载选项"这一层：能不能写由 `Block::write_sectors` 与卷共同决定，
/// 这块卷走的是 `AhciDisk`（真控制器），所以写是真的落盘。
pub fn mount() -> Result<ReadOnlyFs<'static>, VfsError> {
    ReadOnlyFs::mount(&DISK)
}
