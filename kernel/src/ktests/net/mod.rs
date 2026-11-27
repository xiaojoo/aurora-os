//! 网络（`.ktests` 段的一格）。
//!
//! 门控条件逐条照搬自重构前的 `ktests/mod.rs`——它决定这一档编译哪些用例，
//! 改它等于改判定表覆盖的用例集。

#[cfg(feature = "virtio-net")]
mod net;

// ADR-266：ISN/临时端口判据。只依赖 `network::socket`（`handles` 门控），不依赖网卡，故不挂 virtio-net。
#[cfg(feature = "handles")]
mod isn;

// ADR-267：最小防火墙 6 格（不碰网卡，手工造帧直喂 deliver_frame）。门控 = fw（隐含 handles）。
#[cfg(feature = "fw")]
mod fw;
