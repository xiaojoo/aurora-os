from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "kernel" / "fixtures" / "initramfs.cpio"

RECORDS = [
    ("init", 0o100755, b"aurora-init\n"),
    ("etc", 0o040755, b""),
    ("etc/config", 0o100644, b"mode=probe\n"),
    ("dir", 0o040755, b""),
    ("dir/file", 0o100644, bytes(range(64))),
    ("link", 0o120777, b"init"),
]


def align4(data: bytes) -> bytes:
    return data + b"\0" * ((-len(data)) % 4)


def record(ino: int, name: str, mode: int, data: bytes) -> bytes:
    encoded = name.encode("ascii") + b"\0"
    fields = [
        ino, mode, 0, 0, 1, 0, len(data),
        0, 0, 0, 0, len(encoded), 0,
    ]
    header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    assert len(header) == 110
    return align4(header + encoded) + align4(data)


def main() -> None:
    image = b"".join(record(i + 1, *item) for i, item in enumerate(RECORDS))
    image += record(len(RECORDS) + 1, "TRAILER!!!", 0, b"")
    image += b"\0" * ((-len(image)) % 512)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    changed = not OUT.exists() or OUT.read_bytes() != image
    OUT.write_bytes(image)
    print(f"initramfs: {OUT.relative_to(ROOT)} {len(image)} bytes sha256={hashlib.sha256(image).hexdigest()} {'updated' if changed else 'unchanged'}")


if __name__ == "__main__":
    main()
