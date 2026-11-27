//! ADR-260：cpio newc initramfs 只读挂载对象。

pub type Initramfs<'a> = host_initramfs::Initramfs<'a>;
pub type File<'a> = host_initramfs::File<'a>;
pub type Entry = host_initramfs::Entry;
pub type EntryKind = host_initramfs::EntryKind;
pub type InitramfsError = host_initramfs::InitramfsError;
