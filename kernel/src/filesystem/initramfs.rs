//! ADR-260：cpio newc initramfs 只读挂载对象。无分配、无锁、无 unsafe。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitramfsError {
    BadMagic,
    BadHeader,
    BadName,
    Truncated,
    Unsupported,
    TrailingData,
    NotAbsolute,
    BadPath,
    NotFound,
    NotDir,
    IsDir,
    BadOffset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    pub mode: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug)]
struct Record {
    name: usize,
    name_len: usize,
    data: usize,
    size: usize,
    kind: EntryKind,
    mode: u32,
}

pub struct Initramfs<'a> {
    image: &'a [u8],
    entries: usize,
}

pub struct File<'a> {
    data: &'a [u8],
    position: u32,
}

fn hex8(bytes: &[u8]) -> Result<u32, InitramfsError> {
    if bytes.len() != 8 {
        return Err(InitramfsError::BadHeader);
    }
    let mut value = 0u32;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            _ => return Err(InitramfsError::BadHeader),
        };
        value = (value << 4) | digit;
    }
    Ok(value)
}

fn align4(value: usize) -> Result<usize, InitramfsError> {
    value.checked_add(3).map(|v| v & !3).ok_or(InitramfsError::Truncated)
}

fn record_at(image: &[u8], offset: usize) -> Result<(Record, usize), InitramfsError> {
    let header = image.get(offset..offset + 110).ok_or(InitramfsError::Truncated)?;
    if &header[..6] != b"070701" {
        return Err(InitramfsError::BadMagic);
    }
    let mut fields = [0u32; 13];
    for (i, field) in fields.iter_mut().enumerate() {
        *field = hex8(&header[6 + i * 8..14 + i * 8])?;
    }
    if fields[12] != 0 {
        return Err(InitramfsError::BadHeader);
    }
    let mode = fields[1];
    let size = fields[6] as usize;
    let namesize = fields[11] as usize;
    if namesize == 0 {
        return Err(InitramfsError::BadName);
    }
    let name_start = offset + 110;
    let name_end = name_start.checked_add(namesize).ok_or(InitramfsError::Truncated)?;
    let name = image.get(name_start..name_end).ok_or(InitramfsError::Truncated)?;
    if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
        return Err(InitramfsError::BadName);
    }
    #[cfg(not(feature = "fault-initramfs-no-align"))]
    let data = align4(name_end)?;
    #[cfg(feature = "fault-initramfs-no-align")]
    let data = name_end;
    let data_end = data.checked_add(size).ok_or(InitramfsError::Truncated)?;
    if data_end > image.len() {
        return Err(InitramfsError::Truncated);
    }
    let kind = if &name[..name.len() - 1] == b"TRAILER!!!" {
        EntryKind::Dir
    } else {
        match mode & 0o170000 {
            0o100000 => EntryKind::File,
            0o040000 => EntryKind::Dir,
            0o120000 => EntryKind::Symlink,
            _ => return Err(InitramfsError::Unsupported),
        }
    };
    Ok((Record { name: name_start, name_len: namesize - 1, data, size, kind, mode }, align4(data_end)?))
}

fn valid_path(path: &str) -> Result<&[u8], InitramfsError> {
    if !path.starts_with('/') {
        return Err(InitramfsError::NotAbsolute);
    }
    if path.len() > 1 {
        for component in path[1..].split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(InitramfsError::BadPath);
            }
        }
    }
    Ok(path.as_bytes())
}

impl<'a> Initramfs<'a> {
    pub fn mount(image: &'a [u8]) -> Result<Self, InitramfsError> {
        let mut offset = 0usize;
        let mut entries = 0usize;
        loop {
            let (record, next) = record_at(image, offset)?;
            let name = &image[record.name..record.name + record.name_len];
            offset = next;
            if name == b"TRAILER!!!" {
                if record.size != 0 {
                    return Err(InitramfsError::BadHeader);
                }
                if offset > image.len() || image[offset..].iter().any(|&b| b != 0) {
                    return Err(InitramfsError::TrailingData);
                }
                return Ok(Self { image, entries });
            }
            entries += 1;
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries
    }

    pub fn lookup(&self, path: &str) -> Result<Entry, InitramfsError> {
        let path = valid_path(path)?;
        if path == b"/" {
            return Ok(Entry { kind: EntryKind::Dir, mode: 0o040755, size: 0 });
        }
        let wanted = &path[1..];
        let mut offset = 0usize;
        loop {
            let (record, next) = record_at(self.image, offset)?;
            offset = next;
            let name = &self.image[record.name..record.name + record.name_len];
            if name == b"TRAILER!!!" {
                return Err(InitramfsError::NotFound);
            }
            let candidate = name.strip_prefix(b"/").unwrap_or(name);
            if candidate == wanted {
                return Ok(Entry { kind: record.kind, mode: record.mode, size: record.size as u32 });
            }
        }
    }

    pub fn open(&self, path: &str) -> Result<File<'a>, InitramfsError> {
        match self.lookup(path)? {
            Entry { kind: EntryKind::File, size, .. } => {
                let path = valid_path(path)?;
                let wanted = &path[1..];
                let mut offset = 0usize;
                loop {
                    let (record, next) = record_at(self.image, offset)?;
                    offset = next;
                    let name = &self.image[record.name..record.name + record.name_len];
                    if name == b"TRAILER!!!" {
                        return Err(InitramfsError::NotFound);
                    }
                    if name.strip_prefix(b"/").unwrap_or(name) == wanted {
                        return Ok(File {
                            data: &self.image[record.data..record.data + record.size],
                            position: 0,
                        });
                    }
                }
            }
            Entry { kind: EntryKind::Dir, .. } => Err(InitramfsError::IsDir),
            Entry { kind: EntryKind::Symlink, .. } => Err(InitramfsError::Unsupported),
        }
    }
}

impl File<'_> {
    pub fn size(&self) -> u32 {
        self.data.len() as u32
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let left = self.data.len().saturating_sub(self.position as usize);
        let count = dst.len().min(left);
        let start = self.position as usize;
        dst[..count].copy_from_slice(&self.data[start..start + count]);
        self.position += count as u32;
        count
    }

    pub fn seek(&mut self, newpos: u32) -> Result<u32, InitramfsError> {
        if newpos > self.data.len() as u32 {
            return Err(InitramfsError::BadOffset);
        }
        self.position = newpos;
        Ok(newpos)
    }
}
