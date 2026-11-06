# Aurora OS 便携环境（全部落在 H:\aurora-os\.tools，不写系统、不改全局 PATH）
# 用法：在 Git Bash 里  source .tools/env.sh
#
# 两套路径写法各管各的，混用会静默失效（已实测）：
#   - Windows 程序（rustup.exe/cargo.exe）读的环境变量  -> 用 H:/... 形式
#   - Git Bash 自己的 PATH                              -> 必须用 /h/... 形式
export AURORA_ROOT_WIN='H:/aurora-os'
export AURORA_ROOT_POSIX='/h/aurora-os'

export RUSTUP_HOME="$AURORA_ROOT_WIN/.tools/rustup"
export CARGO_HOME="$AURORA_ROOT_WIN/.tools/cargo"

export PATH="$AURORA_ROOT_POSIX/.tools/cargo/bin:$AURORA_ROOT_POSIX/.tools/qemu:$AURORA_ROOT_POSIX/.tools/limine-bin:$PATH"

export AURORA_TARGET_BARE=x86_64-unknown-none
# OVMF 随 QEMU 安装带来；未装 QEMU 时该路径不存在，check 脚本会点名
export OVMF_WIN="$AURORA_ROOT_WIN/.tools/qemu/share/qemu/edk2-x86_64-code.fd"
export OVMF="$AURORA_ROOT_POSIX/.tools/qemu/share/qemu/edk2-x86_64-code.fd"
