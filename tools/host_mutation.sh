#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_BIN="${CARGO:-$ROOT/.tools/cargo/bin/cargo.exe}"
if [[ ! -x "$CARGO_BIN" ]]; then
  CARGO_BIN="cargo"
fi
export CARGO_HOME="${CARGO_HOME:-$ROOT/.tools/cargo}"
cd "$ROOT/crates/host-initramfs"

base_log="$(mktemp)"
mut_log="$(mktemp)"
trap 'rm -f "$base_log" "$mut_log"' EXIT

"$CARGO_BIN" test --quiet >"$base_log" 2>&1 || {
  cat "$base_log"
  echo "HOST-TEST-FAIL(基线)"
  exit 35
}
if "$CARGO_BIN" test --quiet --features fault-initramfs-no-align >"$mut_log" 2>&1; then
  cat "$mut_log"
  echo "MUTATION-NOT-DETECTED: 变异未被测试发现"
  exit 35
fi
if ! grep -q 'data_is_four_byte_aligned_after_name ... FAILED' "$mut_log"; then
  cat "$mut_log"
  echo "MUTATION-WRONG-TARGET: 红点不是专用对齐用例"
  exit 35
fi
echo "HOST-TEST-OK + MUTATION-DETECTED"
