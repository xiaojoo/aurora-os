//! TCP 连接状态机（ADR-198）。
//!
//! ## 这一层的核心设计：状态机是**纯函数**
//!
//! ```
//! pub fn on_segment(st: &mut ConnState, seg: &Segment) -> Reaction
//! ```
//!
//! **不持锁、不碰表、不发包。** 输入是「当前状态 + 收到的段」，输出是「新状态 + 要回什么段」。
//!
//! 这样做的理由与 ADR-197 同一条：**只有纯函数能被判据完整证伪**。
//! 判据可以在一段栈内存上跑完整条握手/挥手路径，不需要网卡、不需要对端、不需要时序。
//!
//! ## 不做的部分（明确）
//!
//! - **重传**：没有定时器，收了就处理，丢了就丢了
//! - **滑动窗口**：窗口字段照填，但**不按对端窗口限制发送**
//! - **拥塞控制**：不读、不算、不实现
//! - **乱序重组**：收到的段必须正好是期望序号，否则丢弃
//!
//! 这些都是「可靠性层」，不在本 ADR 的范围。本 ADR 只证**状态转移本身是对的**。

use crate::network::tcp::{self, Segment};

/// 连接状态（RFC 793 的 11 个状态，`CLOSED` 用槽的 `used=false` 表示）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// 监听：等 SYN。
    Listen,
    /// 已发 SYN，等 SYN-ACK。
    SynSent,
    /// 已收 SYN、已回 SYN-ACK，等 ACK。
    SynReceived,
    /// 连接建立，可收发。
    Established,
    /// 已发 FIN，等对端 ACK。
    FinWait1,
    /// FIN 已确认，等对端 FIN。
    FinWait2,
    /// 收到对端 FIN，已回 ACK（本端还能发）。
    CloseWait,
    /// 已发 FIN 且对端也发了 FIN，等最后的 ACK。
    Closing,
    /// 对端 FIN 已确认，等本端应用关。
    LastAck,
    /// 双方都关了，等 2MSL（今天不实现定时器，直接当终态）。
    TimeWait,
}

impl State {
    /// 这个名字用于日志与判据（**不参与逻辑**）。
    pub fn tag(self) -> &'static str {
        match self {
            State::Listen => "LISTEN",
            State::SynSent => "SYN_SENT",
            State::SynReceived => "SYN_RCVD",
            State::Established => "ESTABLISHED",
            State::FinWait1 => "FIN_WAIT1",
            State::FinWait2 => "FIN_WAIT2",
            State::CloseWait => "CLOSE_WAIT",
            State::Closing => "CLOSING",
            State::LastAck => "LAST_ACK",
            State::TimeWait => "TIME_WAIT",
        }
    }

    /// 这个状态下能不能发数据。
    ///
    /// **`CloseWait` 也算能发**：对端关了写方向，本端还能读到 EOF 之前把剩余数据写完
    /// （RFC 793 §3.5 的「半关闭」）。
    pub fn can_send(self) -> bool {
        matches!(self, State::Established | State::CloseWait)
    }
}

/// 连接的状态（**纯数据**，不含锁、不含槽号）。
#[derive(Clone, Copy, Debug)]
pub struct ConnState {
    pub state: State,
    /// 本端下一个要发的序号（SND.NXT）。
    pub snd_nxt: u32,
    /// 本端已确认的对端序号（RCV.NXT）—— 期望收到的下一个字节。
    pub rcv_nxt: u32,
    /// 初始发送序号（ISS）。挥手判据需要它来算「FIN 的序号」。
    pub iss: u32,
    /// 本端通告的窗口（**今天恒为固定值**，不做窗口缩放）。
    pub rcv_wnd: u16,
}

/// 状态机对收到的一个段的**反应**。
///
/// **不是 `Option<Segment>`**：收段之后有三种可能，用 `Option` 会把「什么都不做」
/// 和「不回但状态变了」混在一起。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reaction {
    /// 什么都不做（状态也没变）。
    Ignore,
    /// 状态变了，但不回段。
    Silent,
    /// 要回一个段（状态可能也变了）。
    Reply(Reply),
}

/// 要回的段。**只描述字段，不构造字节**（构造是 `tcp::build_segment` 的事）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// 载荷长度（回段一般不带载荷；`Reply` 不持有载荷本体）。
    pub payload_len: u16,
}

impl ConnState {
    /// 新建一个**监听**连接。
    pub fn listen(iss: u32) -> Self {
        Self { state: State::Listen, snd_nxt: iss, rcv_nxt: 0, iss, rcv_wnd: 8192 }
    }

    /// 新建一个**主动连接**（SYN_SENT）。
    pub fn connect(iss: u32) -> Self {
        Self { state: State::SynSent, snd_nxt: iss, rcv_nxt: 0, iss, rcv_wnd: 8192 }
    }

    /// 本端要发 SYN 时的段（主动连接用）。
    pub fn syn_segment(&self) -> Reply {
        Reply {
            seq: self.iss,
            ack: 0,
            flags: tcp::SYN,
            window: self.rcv_wnd,
            payload_len: 0,
        }
    }
}

/// **状态转移的纯函数**（ADR-198 的核心）。
///
/// 输入：当前状态（可变）+ 收到的段。输出：反应。
///
/// ## 序号语义
///
/// - `snd_nxt` 在**发出**带 SYN/FIN 的段时前进一格，发数据时前进数据长度；
/// - `rcv_nxt` 在**收到**带 SYN/FIN 的段时前进一格，收数据时前进数据长度；
/// - **两者不同步是常态**（TCP 是全双工）。
pub fn on_segment(st: &mut ConnState, seg: &Segment<'_>) -> Reaction {
    match st.state {
        // ---- LISTEN：等 SYN
        State::Listen => {
            if seg.is_rst() {
                return Reaction::Ignore;
            }
            if !seg.is_syn() {
                // 没 SYN 的段在 LISTEN 上无意义（RFC 793 说可以回 RST，今天选择静默）
                return Reaction::Ignore;
            }
            // 收到 SYN：对端序号 = seg.seq，期望下一个 = seg.seq + 1
            st.rcv_nxt = seg.seq.wrapping_add(1);
            st.state = State::SynReceived;
            // 回 SYN-ACK：本端序号 = iss，确认 = rcv_nxt；**SYN 也占自己一格**
            let r = Reply {
                seq: st.iss,
                ack: st.rcv_nxt,
                flags: tcp::SYN | tcp::ACK,
                window: st.rcv_wnd,
                payload_len: 0,
            };
            st.snd_nxt = st.iss.wrapping_add(1);
            Reaction::Reply(r)
        }

        // ---- SYN_SENT：等 SYN-ACK
        State::SynSent => {
            if seg.is_rst() {
                st.state = State::Listen; // 退回（简化：没有 CLOSED 态，用 Listen 当终态）
                return Reaction::Silent;
            }
            if !seg.is_syn() || !seg.is_ack() {
                return Reaction::Ignore;
            }
            // SYN-ACK：确认号必须是我们的 iss+1
            if seg.ack != st.iss.wrapping_add(1) {
                return Reaction::Ignore;
            }
            st.rcv_nxt = seg.seq.wrapping_add(1);
            st.snd_nxt = st.iss.wrapping_add(1);
            st.state = State::Established;
            // 回 ACK（三次握手的第三步）
            Reaction::Reply(Reply {
                seq: st.snd_nxt,
                ack: st.rcv_nxt,
                flags: tcp::ACK,
                window: st.rcv_wnd,
                payload_len: 0,
            })
        }

        // ---- SYN_RECEIVED：等第三次握手的 ACK
        State::SynReceived => {
            if seg.is_rst() {
                st.state = State::Listen;
                return Reaction::Silent;
            }
            if !seg.is_ack() {
                return Reaction::Ignore;
            }
            if seg.ack != st.snd_nxt {
                return Reaction::Ignore;
            }
            st.state = State::Established;
            Reaction::Silent
        }

        // ---- ESTABLISHED：数据 + FIN
        State::Established => handle_data_or_fin(st, seg),

        // ---- CLOSE_WAIT：对端已关写方向，本端还能发
        State::CloseWait => {
            if seg.is_fin() {
                return Reaction::Ignore; // 重复 FIN：ACK 一下（简化：忽略）
            }
            // 还能收数据（对端可能在半关闭前发的还在路上）
            if !seg.payload.is_empty() {
                if seg.seq != st.rcv_nxt {
                    return Reaction::Ignore;
                }
                st.rcv_nxt = st.rcv_nxt.wrapping_add(seg.payload.len() as u32);
            }
            // 迟到的 ACK 不改变状态
            Reaction::Silent
        }

        // ---- FIN_WAIT1：等本端 FIN 的 ACK
        State::FinWait1 => {
            if seg.is_ack() && seg.ack == st.snd_nxt {
                // 本端 FIN 被确认
                if seg.is_fin() {
                    // 对端同时关了（FIN 与 ACK 同来）
                    st.rcv_nxt = seg.seq.wrapping_add(1);
                    st.state = State::TimeWait;
                    return Reaction::Reply(Reply {
                        seq: st.snd_nxt,
                        ack: st.rcv_nxt,
                        flags: tcp::ACK,
                        window: st.rcv_wnd,
                        payload_len: 0,
                    });
                }
                st.state = State::FinWait2;
                return Reaction::Silent;
            }
            Reaction::Ignore
        }

        // ---- FIN_WAIT2：等对端 FIN
        State::FinWait2 => {
            if seg.is_fin() {
                if seg.seq != st.rcv_nxt {
                    return Reaction::Ignore;
                }
                st.rcv_nxt = st.rcv_nxt.wrapping_add(1);
                st.state = State::TimeWait;
                return Reaction::Reply(Reply {
                    seq: st.snd_nxt,
                    ack: st.rcv_nxt,
                    flags: tcp::ACK,
                    window: st.rcv_wnd,
                    payload_len: 0,
                });
            }
            Reaction::Ignore
        }

        // ---- LAST_ACK：等本端 FIN 的 ACK
        State::LastAck => {
            if seg.is_ack() && seg.ack == st.snd_nxt {
                st.state = State::TimeWait;
                return Reaction::Silent;
            }
            Reaction::Ignore
        }

        // ---- CLOSING：等都确认
        State::Closing => {
            if seg.is_ack() && seg.ack == st.snd_nxt {
                st.state = State::TimeWait;
                return Reaction::Silent;
            }
            Reaction::Ignore
        }

        // ---- TIME_WAIT：终态（2MSL 定时器不实现）
        State::TimeWait => Reaction::Ignore,
    }
}

/// `ESTABLISHED` 与 `CLOSE_WAIT` 共用的「数据或 FIN」处理。
fn handle_data_or_fin(st: &mut ConnState, seg: &Segment<'_>) -> Reaction {
    if seg.is_rst() {
        st.state = State::Listen;
        return Reaction::Silent;
    }
    // FIN 先处理：它会消耗一个序号
    if seg.is_fin() {
        // FIN 的序号 = seg.seq + payload 长度
        let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
        if seg.seq != st.rcv_nxt {
            return Reaction::Ignore; // 序号不对：简化，丢弃
        }
        let _ = fin_seq;
        st.rcv_nxt = seg.seq.wrapping_add(seg.payload.len() as u32).wrapping_add(1);
        // 本端进入 CLOSE_WAIT（对端关了写方向）
        st.state = State::CloseWait;
        return Reaction::Reply(Reply {
            seq: st.snd_nxt,
            ack: st.rcv_nxt,
            flags: tcp::ACK,
            window: st.rcv_wnd,
            payload_len: 0,
        });
    }
    // 纯数据
    if !seg.payload.is_empty() {
        if seg.seq != st.rcv_nxt {
            return Reaction::Ignore; // 乱序：简化，丢弃
        }
        st.rcv_nxt = st.rcv_nxt.wrapping_add(seg.payload.len() as u32);
        return Reaction::Reply(Reply {
            seq: st.snd_nxt,
            ack: st.rcv_nxt,
            flags: tcp::ACK,
            window: st.rcv_wnd,
            payload_len: 0,
        });
    }
    // 纯 ACK：不改变状态
    Reaction::Silent
}

/// 本端主动关：返回要发的 FIN 段（并推进 `snd_nxt`）。
///
/// **状态不对时回 `None`**：只有 `ESTABLISHED` 能主动关。
pub fn close_send_fin(st: &mut ConnState) -> Option<Reply> {
    if st.state != State::Established {
        return None;
    }
    st.state = State::FinWait1;
    let r = Reply {
        seq: st.snd_nxt,
        ack: st.rcv_nxt,
        flags: tcp::FIN | tcp::ACK,
        window: st.rcv_wnd,
        payload_len: 0,
    };
    st.snd_nxt = st.snd_nxt.wrapping_add(1); // FIN 占一格
    Some(r)
}

/// 本端从 `CLOSE_WAIT` 关：返回要发的 FIN 段。
pub fn close_send_fin_from_close_wait(st: &mut ConnState) -> Option<Reply> {
    if st.state != State::CloseWait {
        return None;
    }
    st.state = State::LastAck;
    let r = Reply {
        seq: st.snd_nxt,
        ack: st.rcv_nxt,
        flags: tcp::FIN | tcp::ACK,
        window: st.rcv_wnd,
        payload_len: 0,
    };
    st.snd_nxt = st.snd_nxt.wrapping_add(1);
    Some(r)
}