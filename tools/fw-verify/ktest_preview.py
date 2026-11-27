"""预演 kernel/src/ktests/net/fw.rs 的 t_fw_malformed（Python 模型，**不是内核实跑**）。

用途：证明那一格的三个"防空转证人"阈值在模型里是可达的、且不是恒真：
  (a) v4 截断帧全部不判（evaluated 增量 0）；
  (b) NDP 截断 21..86 恰好 65 帧被"取不出头即丢"；
  (c) 4096 轮头部变异里 evaluated 与 malformed 都前进（模型给出 +2513 / +443；内核帧的校验和/MAC 字节与模型不同，
      所以内核里的具体数会不同，ktest 只断言 > 0）。
运行：与 run_all.py 相同的注入方式（见 README），调用 preview(M)。
"""


def preview(M):
    MASK = (1 << 64) - 1
    ours = bytes.fromhex("fe800000000000000000000000000001")
    peer = bytes.fromhex("fe800000000000000000000000000099")
    f4 = M.build_udp4(bytes([10, 0, 2, 2]), bytes([10, 0, 2, 15]), 40000, 47004, b"fw-267")
    na = M.build_nd(peer, ours, 136, peer)
    fw = M.FwState()
    fw.load(M.assemble([M.ret(1)]), True)
    socks = {47004}
    out = {"len_v4": len(f4), "len_na": len(na)}
    e0 = fw.evaluated
    out["a_trunc_all_zero"] = all(M.deliver_frame_model(f4[:k], fw, socks)[0] == 0 for k in range(len(f4)))
    out["a_eval_delta"] = fw.evaluated - e0
    m0 = fw.malformed
    out["b_nd_trunc_all_zero"] = all(M.deliver_frame_model(na[:k], fw, socks)[0] == 0 for k in range(21, len(na)))
    out["b_malformed_delta"] = fw.malformed - m0
    e2, m2 = fw.evaluated, fw.malformed
    x = 0x2675
    for i in range(4096):
        x ^= (x << 13) & MASK
        x ^= x >> 7
        x ^= (x << 17) & MASK
        src = f4 if i % 2 == 0 else na
        b = bytearray(src)
        n = len(src)
        b[12 + (x % max(n - 12, 1))] ^= ((x >> 32) & 0xFF) | 1
        cut = ((x >> 8) % (n + 1)) if (x & 0x30) == 0 else n
        M.deliver_frame_model(bytes(b[:cut]), fw, socks)
    out["c_eval_delta"] = fw.evaluated - e2
    out["c_malformed_delta"] = fw.malformed - m2
    out["c_faults"] = fw.faults
    return out
