//! 内核内测试表（手册 §12.2 的段注册方案）。
//!
//! 稳定版没有自定义测试框架，因此用 `.ktests` 段收集 `&'static KTest`，
//! 由链接脚本提供的 `__ktests_start/__ktests_end` 定界。
//!
//! **表为空必须判失败**：否则“一条用例都没注册进来”和“全部通过”长得一样，
//! 这就是§12.3 R19 说要防的“绿而无效”。

use crate::serial;

#[repr(C)]
pub struct KTest {
    pub name: &'static str,
    pub run: fn() -> bool,
}

/// 注册一条内核用例。测试体写成具名函数，避免闭包转 fn 指针在 static 初始化的限制。
#[macro_export]
macro_rules! ktest {
    ($static_name:ident, $fn_name:ident) => {
        #[used]
        #[link_section = ".ktests"]
        static $static_name: $crate::ktest::KTest = $crate::ktest::KTest {
            name: stringify!($fn_name),
            run: $fn_name,
        };
    };
}

extern "C" {
    static __ktests_start: u8;
    static __ktests_end: u8;
}

pub struct Summary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    /// 表不可用（空、或长度不按 KTest 对齐）——与“失败”区分
    pub table_invalid: bool,
}

pub fn run_all() -> Summary {
    let start = &raw const __ktests_start as usize;
    let end = &raw const __ktests_end as usize;
    let bytes = end.saturating_sub(start);
    let size = core::mem::size_of::<KTest>();

    if bytes == 0 || !bytes.is_multiple_of(size) {
        serial::line("fatal", format_args!("ktest table invalid: start={:#x} end={:#x} bytes={}", start, end, bytes));
        return Summary { total: 0, passed: 0, failed: 0, table_invalid: true };
    }

    // SAFETY: 地址与长度取自链接脚本给出的段边界，且上面已确认长度是 KTest 大小的整数倍；
    // 段内每个条目都由 ktest! 宏生成的合法 KTest。
    let tests = unsafe { core::slice::from_raw_parts(start as *const KTest, bytes / size) };

    let mut passed = 0usize;
    let mut failed = 0usize;
    for t in tests {
        let ok = (t.run)();
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
        serial::line(if ok { "test" } else { "FAIL" }, format_args!("{} -> {}", t.name, if ok { "ok" } else { "failed" }));
    }
    Summary { total: tests.len(), passed, failed, table_invalid: false }
}
