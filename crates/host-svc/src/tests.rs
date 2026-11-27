//! host-svc 宿主机测试（`cargo test -p host-svc`）。**未在本沙箱运行**（无 Rust 工具链）；
//! 每一格在 `tools/svc-verify/svc_model.py` 的 Python 等价移植里有同形检验与变异结果（见该目录 results.json）。
//! 零外部依赖：自带 xorshift，种子固定，失败可复现。

use crate::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

const OK_UNIT: &[u8] = b"name=httpd\nexec=/HTTPD.ELF\nrestart=on-failure\nbackoff_ms=200,1000,5000\nmax_per_minute=5\n";

fn unit(max: u32, restart: Restart, table: &[u32]) -> Unit {
    let mut u = Unit::blank();
    u.max_per_minute = max;
    u.restart = restart;
    for (i, v) in table.iter().enumerate() {
        u.backoff[i] = *v;
    }
    u.backoff_len = table.len();
    u
}

// ---------------------------------------------------------------- 解析
#[test]
fn parse_ok_roundtrip() {
    let u = parse_unit(OK_UNIT).unwrap_or_else(|_| Unit::blank());
    assert_eq!(u.name(), b"httpd");
    assert_eq!(u.exec(), b"/HTTPD.ELF");
    assert_eq!(u.restart, Restart::OnFailure);
    assert_eq!(u.backoff(), &[200, 1000, 5000]);
    assert_eq!(u.max_per_minute, 5);
}

#[test]
fn parse_defaults_when_optional_missing() {
    let u = parse_unit(b"name=a\nexec=/A.ELF\n").unwrap_or_else(|_| Unit::blank());
    assert_eq!(u.restart, Restart::OnFailure);
    assert_eq!(u.backoff(), &[200, 1000, 5000]);
    assert_eq!(u.max_per_minute, 5);
}

#[test]
fn parse_comments_blank_crlf_and_no_trailing_newline() {
    let u = parse_unit(b"# c\r\n\r\nname=a\r\n  exec = /A.ELF  ").unwrap_or_else(|_| Unit::blank());
    assert_eq!(u.name(), b"a");
    assert_eq!(u.exec(), b"/A.ELF");
}

#[test]
fn parse_rejects_each_class() {
    assert_eq!(parse_unit(b"name=a\nexec=/A\nname=b\n").err(), Some(ParseErr::DupKey));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nbogus=1\n").err(), Some(ParseErr::UnknownKey));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nnoequals\n").err(), Some(ParseErr::NoEquals));
    assert_eq!(parse_unit(b"name=a\n").err(), Some(ParseErr::Missing));
    assert_eq!(parse_unit(b"exec=/A\n").err(), Some(ParseErr::Missing));
    assert_eq!(parse_unit(b"").err(), Some(ParseErr::Missing));
    assert_eq!(parse_unit(b"name=\nexec=/A\n").err(), Some(ParseErr::BadValue));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nrestart=sometimes\n").err(), Some(ParseErr::BadValue));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nmax_per_minute=x\n").err(), Some(ParseErr::BadNumber));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nmax_per_minute=99999999999\n").err(), Some(ParseErr::BadNumber));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nmax_per_minute=17\n").err(), Some(ParseErr::TooManyPerMinute));
    assert_eq!(parse_unit(b"name=a\0b\nexec=/A\n").err(), Some(ParseErr::BadBytes));
    assert_eq!(parse_unit(&[0xff, 0xfe]).err(), Some(ParseErr::BadBytes));
}

#[test]
fn parse_boundaries_name_exec_backoff_ring() {
    let mut n = [b'x'; NAME_MAX + 1];
    let mut buf = std::vec::Vec::new();
    buf.extend_from_slice(b"name=");
    buf.extend_from_slice(&n[..NAME_MAX]);
    buf.extend_from_slice(b"\nexec=/A\n");
    assert!(parse_unit(&buf).is_ok(), "恰好 NAME_MAX 应接受");
    n[NAME_MAX] = b'y';
    let mut over = std::vec::Vec::new();
    over.extend_from_slice(b"name=");
    over.extend_from_slice(&n);
    over.extend_from_slice(b"\nexec=/A\n");
    assert_eq!(parse_unit(&over).err(), Some(ParseErr::BadValue), "NAME_MAX+1 应拒绝");
    assert!(parse_unit(b"name=a\nexec=/A\nbackoff_ms=1,2,3,4,5,6,7,8\n").is_ok());
    assert_eq!(parse_unit(b"name=a\nexec=/A\nbackoff_ms=1,2,3,4,5,6,7,8,9\n").err(), Some(ParseErr::BadBackoff));
    assert_eq!(parse_unit(b"name=a\nexec=/A\nbackoff_ms=\n").err(), Some(ParseErr::BadNumber));
    assert!(parse_unit(b"name=a\nexec=/A\nmax_per_minute=16\n").is_ok());
    assert!(parse_unit(b"name=a\nexec=/A\nmax_per_minute=0\n").is_ok());
}

#[test]
fn parse_never_panics_on_garbage() {
    let mut r = Rng(0x1234_5678_9abc_def1);
    let alpha = b"name=exec/\n#, 0123456789.ELFabcdefgrstuvw\r\t\0\xff";
    for _ in 0..30_000 {
        let len = r.below(80) as usize;
        let v: std::vec::Vec<u8> = (0..len).map(|_| alpha[r.below(alpha.len() as u64) as usize]).collect();
        let _ = parse_unit(&v);
    }
}

// ---------------------------------------------------------------- 退避表
#[test]
fn backoff_table_indexing_and_clamp() {
    let t = [200, 1000, 5000];
    assert_eq!(next_delay(0, &t), Some(200));
    assert_eq!(next_delay(1, &t), Some(1000));
    assert_eq!(next_delay(2, &t), Some(5000));
    assert_eq!(next_delay(3, &t), Some(5000), "越界取末项");
    assert_eq!(next_delay(u32::MAX, &t), Some(5000));
    assert_eq!(next_delay(0, &[]), None, "空表无延迟");
    assert_eq!(next_delay(7, &[42]), Some(42), "单项表");
}

// ---------------------------------------------------------------- 熔断
#[test]
fn breaker_trips_strictly_above_max() {
    let u = unit(3, Restart::Always, &[10]);
    let mut b = Breaker::new();
    // 前 3 次（== max）仍允许重启，第 4 次才熔断。
    for i in 0..3u64 {
        assert_eq!(on_exit(&u, &mut b, i as u32, Exit::Failed, 1000 + i), Action::RestartAfter(10), "第{}次", i + 1);
    }
    assert_eq!(on_exit(&u, &mut b, 3, Exit::Failed, 1003), Action::MarkFailed);
}

#[test]
fn breaker_window_edges() {
    let u = unit(1, Restart::Always, &[10]);
    let mut b = Breaker::new();
    assert_eq!(on_exit(&u, &mut b, 0, Exit::Failed, 0), Action::RestartAfter(10));
    // 恰好 WINDOW_MS 之后：旧记录已出窗口（`< WINDOW_MS` 才算窗口内）⇒ 又只有 1 次 ⇒ 不熔断
    assert_eq!(on_exit(&u, &mut b, 1, Exit::Failed, WINDOW_MS), Action::RestartAfter(10));
    // 窗口内再来一次 ⇒ 熔断
    let mut b2 = Breaker::new();
    let _ = on_exit(&u, &mut b2, 0, Exit::Failed, 0);
    assert_eq!(on_exit(&u, &mut b2, 1, Exit::Failed, WINDOW_MS - 1), Action::MarkFailed);
}

#[test]
fn breaker_zero_max_means_no_restart_at_all() {
    let u = unit(0, Restart::Always, &[10]);
    let mut b = Breaker::new();
    assert_eq!(on_exit(&u, &mut b, 0, Exit::Failed, 5), Action::MarkFailed, "max=0 ⇒ 第一次退出即熔断");
}

#[test]
fn breaker_clock_going_backwards_does_not_panic() {
    let u = unit(5, Restart::Always, &[10]);
    let mut b = Breaker::new();
    let _ = on_exit(&u, &mut b, 0, Exit::Failed, 1_000_000);
    // now 倒退：saturating_sub ⇒ 差 0 ⇒ 视为窗口内
    let _ = on_exit(&u, &mut b, 1, Exit::Failed, 5);
    assert!(b.len() >= 1);
}

#[test]
fn breaker_ring_full_is_bounded() {
    let u = unit(RING_MAX as u32, Restart::Always, &[1]);
    let mut b = Breaker::new();
    for i in 0..1000u64 {
        let _ = on_exit(&u, &mut b, 0, Exit::Failed, i);
        assert!(b.len() <= RING_MAX + 1, "环长度不得越界");
    }
}

#[test]
fn breaker_max_16_trips_on_seventeenth() {
    let u = unit(16, Restart::Always, &[1]);
    let mut b = Breaker::new();
    for i in 0..16u64 {
        assert_eq!(on_exit(&u, &mut b, i as u32, Exit::Failed, i), Action::RestartAfter(1));
    }
    assert_eq!(on_exit(&u, &mut b, 16, Exit::Failed, 16), Action::MarkFailed);
}

// ---------------------------------------------------------------- 策略
#[test]
fn policy_matrix() {
    for (rst, ex, want_restart) in [
        (Restart::Never, Exit::Failed, false),
        (Restart::Never, Exit::Clean, false),
        (Restart::OnFailure, Exit::Failed, true),
        (Restart::OnFailure, Exit::Clean, false),
        (Restart::Always, Exit::Failed, true),
        (Restart::Always, Exit::Clean, true),
    ] {
        let u = unit(5, rst, &[10]);
        let mut b = Breaker::new();
        let got = matches!(on_exit(&u, &mut b, 0, ex, 1), Action::RestartAfter(_));
        assert_eq!(got, want_restart, "{:?}/{:?}", rst, ex);
    }
}

#[test]
fn exit_from_code() {
    assert_eq!(Exit::from_code(0), Exit::Clean);
    assert_eq!(Exit::from_code(1), Exit::Failed);
    assert_eq!(Exit::from_code(u32::MAX), Exit::Failed);
}

#[test]
fn empty_backoff_table_yields_none_not_panic() {
    let u = unit(5, Restart::Always, &[]);
    let mut b = Breaker::new();
    assert_eq!(on_exit(&u, &mut b, 0, Exit::Failed, 1), Action::None);
}

/// 重启风暴证人：以极短间隔连续退出，必须在 `max+1` 次内熔断，且熔断后**持续**熔断（不会自己恢复）。
#[test]
fn restart_storm_trips_and_stays_tripped() {
    let u = unit(5, Restart::Always, &[1]);
    let mut b = Breaker::new();
    let mut first_trip = None;
    for i in 0..50u64 {
        if on_exit(&u, &mut b, 0, Exit::Failed, i) == Action::MarkFailed && first_trip.is_none() {
            first_trip = Some(i);
        }
    }
    assert_eq!(first_trip, Some(5), "第 6 次（下标 5）熔断");
    assert_eq!(on_exit(&u, &mut b, 0, Exit::Failed, 60), Action::MarkFailed, "仍在窗口内 ⇒ 持续熔断");
}
