use crate::filesystem::initramfs::{EntryKind, Initramfs, InitramfsError};
use crate::ktest;

const IMAGE: &[u8] = include_bytes!("../../../fixtures/initramfs.cpio");

fn t_initramfs_core() -> bool {
    let fs = match Initramfs::mount(IMAGE) {
        Ok(fs) => fs,
        Err(error) => {
            crate::log_fatal!("initramfs: mount 失败 {:?}", error);
            return false;
        }
    };
    let count = fs.entry_count() == 6;
    let root = fs.lookup("/") == Ok(initramfs_entry(EntryKind::Dir, 0o040755, 0));
    let init_meta = fs.lookup("/init") == Ok(initramfs_entry(EntryKind::File, 0o100755, 12));
    let config_meta = fs.lookup("/etc/config") == Ok(initramfs_entry(EntryKind::File, 0o100644, 11));
    let neighbor_meta = fs.lookup("/dir/file") == Ok(initramfs_entry(EntryKind::File, 0o100644, 64));
    let link_meta = fs.lookup("/link") == Ok(initramfs_entry(EntryKind::Symlink, 0o120777, 4));

    let mut init = match fs.open("/init") {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut init_bytes = [0u8; 12];
    let init_read = init.read(&mut init_bytes) == 12 && init_bytes == *b"aurora-init\n";
    let init_hash = crate::ahci::fnv1a64(&init_bytes);
    let eof = init.read(&mut init_bytes) == 0;
    let seek = init.seek(2) == Ok(2)
        && init.read(&mut init_bytes[..4]) == 4
        && &init_bytes[..4] == b"rora";
    let bad_seek = init.seek(13) == Err(InitramfsError::BadOffset);
    let dir_open = matches!(fs.open("/etc"), Err(InitramfsError::IsDir));
    let link_open = matches!(fs.open("/link"), Err(InitramfsError::Unsupported));
    let missing = fs.lookup("/missing") == Err(InitramfsError::NotFound);
    let relative = fs.lookup("init") == Err(InitramfsError::NotAbsolute);
    let bad_path = fs.lookup("/etc/../init") == Err(InitramfsError::BadPath);

    let mut config = match fs.open("/etc/config") {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut config_bytes = [0u8; 11];
    let config_read = config.read(&mut config_bytes) == 11;
    let mut neighbor = match fs.open("/dir/file") {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut neighbor_bytes = [0u8; 64];
    let neighbor_read = neighbor.read(&mut neighbor_bytes) == 64
        && neighbor_bytes.iter().enumerate().all(|(i, b)| *b == i as u8);

    let ok = count && root && init_meta && config_meta && neighbor_meta && link_meta
        && init_read && eof && seek && bad_seek && dir_open && link_open && missing && relative && bad_path
        && config_read && neighbor_read;
    crate::log_info!(
        "initramfs: entries={} init_sha={:016x} config_sha={:016x} neighbor_sha={:016x} eof={} seek={} errors={} ⇒ {}",
        fs.entry_count(),
        init_hash,
        crate::ahci::fnv1a64(&config_bytes),
        crate::ahci::fnv1a64(&neighbor_bytes),
        eof,
        seek && bad_seek,
        dir_open && link_open && missing && relative && bad_path,
        ok,
    );
    ok
}

fn initramfs_entry(kind: EntryKind, mode: u32, size: u32) -> crate::filesystem::initramfs::Entry {
    crate::filesystem::initramfs::Entry { kind, mode, size }
}

fn t_initramfs_corrupt() -> bool {
    let mut bad_magic = [0u8; 1024];
    bad_magic.copy_from_slice(IMAGE);
    bad_magic[0] = b'X';
    let magic = matches!(Initramfs::mount(&bad_magic), Err(InitramfsError::BadMagic));
    let truncated = matches!(Initramfs::mount(&IMAGE[..100]), Err(InitramfsError::Truncated));
    let mut bad_name = [0u8; 1024];
    bad_name.copy_from_slice(IMAGE);
    bad_name[110] = 0;
    let name = matches!(Initramfs::mount(&bad_name), Err(InitramfsError::BadName));
    let mut trailing = [0u8; 1025];
    trailing[..IMAGE.len()].copy_from_slice(IMAGE);
    trailing[IMAGE.len()] = 1;
    let tail = matches!(Initramfs::mount(&trailing), Err(InitramfsError::TrailingData));
    let ok = magic && truncated && name && tail;
    crate::log_info!("initramfs-corrupt: magic={} truncated={} name={} trailing={} ⇒ {}", magic, truncated, name, tail, ok);
    ok
}

ktest!(KT_INITRAMFS_CORE, t_initramfs_core);
ktest!(KT_INITRAMFS_CORRUPT, t_initramfs_corrupt);
