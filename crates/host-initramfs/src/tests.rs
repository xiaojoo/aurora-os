//! 宿主机测试（S1-3）。不依赖内核；用本文件里的最小 newc 构造器造镜像。
//! 变异证红：`cargo test --features fault-initramfs-no-align` 时，凡含“非 4 对齐名长”的用例必须红
//! （见 `#[cfg(not(feature = ...))]` 门控的用例与 CI 脚本 tools/host_mutation.sh）。
use super::*;

/// 追加一条 newc 记录（头 110 字节 + 名 + 对齐 + 数据 + 对齐）。mode 用 POSIX st_mode。
fn push(img: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
    let namesz = name.len() + 1;
    let mut h = String::from("070701");
    let fields = [0u32 /*ino*/, mode, 0, 0, 1 /*nlink*/, 0 /*mtime*/, data.len() as u32,
                  0, 0, 0, 0, namesz as u32, 0 /*check*/];
    for f in fields { h.push_str(&format!("{:08X}", f)); }
    assert_eq!(h.len(), 110);
    img.extend_from_slice(h.as_bytes());
    img.extend_from_slice(name.as_bytes()); img.push(0);
    while img.len() % 4 != 0 { img.push(0); }
    img.extend_from_slice(data);
    while img.len() % 4 != 0 { img.push(0); }
}
fn build(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut img = Vec::new();
    for (n, m, d) in entries { push(&mut img, n, *m, d); }
    push(&mut img, "TRAILER!!!", 0, &[]);
    img
}
const F: u32 = 0o100644; const D: u32 = 0o040755; const L: u32 = 0o120777;

#[test]
fn mount_counts_entries_and_looks_up() {
    let img = build(&[("bin", D, b""), ("bin/init", F, b"INIT-DATA"), ("etc/motd", F, b"hi")]);
    let fs = Initramfs::mount(&img).unwrap();
    assert_eq!(fs.entry_count(), 3);
    let e = fs.lookup("/bin/init").unwrap();
    assert_eq!((e.kind, e.size), (EntryKind::File, 9));
    assert_eq!(fs.lookup("/").unwrap().kind, EntryKind::Dir);
    assert_eq!(fs.lookup("/nope"), Err(InitramfsError::NotFound));
}

#[test]
fn open_read_seek_eof() {
    let img = build(&[("a", F, b"0123456789")]);
    let fs = Initramfs::mount(&img).unwrap();
    let mut f = fs.open("/a").unwrap();
    let mut b = [0u8; 4];
    assert_eq!(f.read(&mut b), 4); assert_eq!(&b, b"0123");
    assert_eq!(f.seek(8), Ok(8));
    assert_eq!(f.read(&mut b), 2); assert_eq!(&b[..2], b"89");
    assert_eq!(f.read(&mut b), 0);                      // EOF
    assert_eq!(f.seek(10), Ok(10));                     // 恰好等于长度合法
    assert_eq!(f.seek(11), Err(InitramfsError::BadOffset));
}

#[test]
fn dir_and_symlink_are_refused() {
    let img = build(&[("d", D, b""), ("l", L, b"/a")]);
    let fs = Initramfs::mount(&img).unwrap();
    assert!(matches!(fs.open("/d"), Err(InitramfsError::IsDir)));
    assert!(matches!(fs.open("/l"), Err(InitramfsError::Unsupported)));
}

#[test]
fn path_validation() {
    let img = build(&[("a", F, b"x")]);
    let fs = Initramfs::mount(&img).unwrap();
    for p in ["a", "/a/", "/a//b", "/./a", "/../a", "/a/../a"] {
        assert!(fs.lookup(p).is_err(), "{p} 应被拒");
    }
    assert_eq!(fs.lookup("a"), Err(InitramfsError::NotAbsolute));
}

#[test]
fn bad_magic_header_name_and_truncation() {
    let mut img = build(&[("a", F, b"x")]);
    img[0] = b'X';
    assert_eq!(Initramfs::mount(&img).err(), Some(InitramfsError::BadMagic));
    let img = build(&[("a", F, b"x")]);
    assert_eq!(Initramfs::mount(&img[..50]).err(), Some(InitramfsError::Truncated));
    // 头里混入非十六进制字符
    let mut img = build(&[("a", F, b"x")]);
    img[10] = b'Z';
    assert_eq!(Initramfs::mount(&img).err(), Some(InitramfsError::BadHeader));
}

#[test]
fn trailing_nonzero_data_is_rejected() {
    let mut img = build(&[("a", F, b"x")]);
    img.extend_from_slice(&[0, 0, 7]);
    assert_eq!(Initramfs::mount(&img).err(), Some(InitramfsError::TrailingData));
    let mut ok = build(&[("a", F, b"x")]);
    ok.extend_from_slice(&[0, 0, 0, 0]);
    assert!(Initramfs::mount(&ok).is_ok());            // 零尾填充合法
}

/// 对齐：名长使 name_end 不是 4 的倍数时，数据必须从下一个 4 对齐处开始。
/// `fault-initramfs-no-align` 打开时该用例必须红（变异证红）。
#[test]
fn data_is_four_byte_aligned_after_name() {
    // 名 "ab" → namesz=3 → 110+3=113，不是 4 的倍数
    let img = build(&[("ab", F, b"PAYLOAD")]);
    let fs = Initramfs::mount(&img).unwrap();
    let mut f = fs.open("/ab").unwrap();
    let mut b = [0u8; 7];
    assert_eq!(f.read(&mut b), 7);
    assert_eq!(&b, b"PAYLOAD");
}

/// 已知行为（**不改**，仅钉住）：`File::read` 的 `position += count as u32` 对 >4 GiB 数据会回绕；
/// 但 `size` 字段本身是 u32（≤4 GiB），故 position 不会超过 u32::MAX。此处只验证上界不变量。
#[test]
fn position_never_exceeds_size() {
    let img = build(&[("a", F, &[7u8; 100])]);
    let fs = Initramfs::mount(&img).unwrap();
    let mut f = fs.open("/a").unwrap();
    let mut big = [0u8; 500];
    assert_eq!(f.read(&mut big), 100);
    assert_eq!(f.position(), 100);
    assert_eq!(f.read(&mut big), 0);
    assert_eq!(f.position(), 100);
}

mod props {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        /// 任意字节输入：mount/lookup/open 绝不 panic（只允许返回 Err）。
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Ok(fs) = Initramfs::mount(&bytes) {
                let _ = fs.lookup("/a");
                let _ = fs.open("/a");
            }
        }
        /// 合法镜像往返：任意名称(去掉非法字符)与数据，读出必须等于写入。
        #[test]
        fn roundtrip(name in "[a-z]{1,12}", data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let img = build(&[(name.as_str(), F, data.as_slice())]);
            let fs = Initramfs::mount(&img).unwrap();
            let mut f = fs.open(&format!("/{name}")).unwrap();
            let mut out = vec![0u8; data.len()];
            prop_assert_eq!(f.read(&mut out), data.len());
            prop_assert_eq!(out, data);
        }
        /// 单字节翻转后：要么仍可解析，要么返回 Err；不 panic、不越界读（Miri 下同样）。
        #[test]
        fn single_bitflip_is_safe(idx in 0usize..300, bit in 0u8..8) {
            let mut img = build(&[("bin", D, b""), ("bin/init", F, b"INIT"), ("x", F, b"yy")]);
            let i = idx % img.len();
            img[i] ^= 1 << bit;
            if let Ok(fs) = Initramfs::mount(&img) { let _ = fs.lookup("/bin/init"); let _ = fs.open("/x"); }
        }
    }
}
