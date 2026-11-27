# ADR-261：内核 CSPRNG 与熵不足拒产

状态：**已采纳**（2026-11-27；使用者批准新增 `RANK_RAND=41`、`security::rand` 接口与 RDRAND/RDSEED unsafe；合并试验通过）。
关联：S1 代码变更清单、ADR-080（验签只检测不拒启）、ADR-260（initramfs 宿主可测拆分）、BACKLOG S1 合并试验。

## 背景

内核此前没有 CSPRNG；TCP 初始序号仍是确定性槽号/世代组合。S1 附件提出 ChaCha20、
SHA-256 熵混合、RDRAND/RDSEED/TSC 三路熵源与独立锁，但附件未编译，且误以为
`CpuFeatures` 已有 `rdseed` 字段。日志格式化会走全局分配器，因此播种不能紧贴
`handle::init()`，必须晚于堆初始化。

## 决定

1. 新增 `security::rand`，启动阶段在 `stage_memory()` 之后、CPU 保护与 ktests 之前调用
   `init()`。本片不新增 syscall，不把 TCP ISS 切换到随机数；确定性 ISS 是仍未关闭的风险。
2. `fill()` / `next_u64()` 在熵不足时返回 `NotSeeded`，不输出低质量回退值。RDRAND、
   RDSEED、TSC 抖动三路中至少两路成功才置 `seeded`；同一路重复混入只计一次。
   RDRAND/RDSEED 各收集四个 `u64`（32 字节）；`fault-rand-no-entropy` 关闭三路采集，
   用于证明零熵时 `fill()` 必须回 `NotSeeded`。
3. ChaCha20 使用 RFC 8439 块函数、64 位计数器与零 nonce；熵混合使用既有 SHA-256。
   每输出 256 块用自身输出更换密钥。该实现只在本 ADR 范围内使用，不宣称完成密码学审计。
4. 熵池状态由新增叶子锁 `RANK_RAND=41` 保护。持锁期间不分配、不打日志、不获取其他锁。
   启动期单线程播种；重入负样本必须升 L4。
5. RDRAND/RDSEED 仅在 CPUID 对应位确认后执行，最多重试 10 次，只写调用方栈上的 `u64`。
   两处 intrinsic 登记为 U1；CPUID 查询本身是安全封装，不新增 unsafe。
6. 核内 ktest 同时验证块函数输出、熵源计数与 seeded/fill 的一致性；宿主用独立实现对账
   固定 key/counter 的 16 个字。变异必须能咬到对应判据。

## 后果

- QEMU 与真机都必须实测熵源读数；真机未验证前不能宣称 CSPRNG 已在真机交付。
- 未接入 TCP 的 `NotSeeded` 消费者不存在；后续接入 ISS 时必须显式处理错误，禁止回退到确定性值。
- 新锁与 unsafe 都进入锁序、白名单和逐处普查；接口变更触发 `check-interface-change`。

## 验收（2026-11-27）

- 宿主 `host-initramfs` 单测 **11/11**；对齐变异下专用用例 `data_is_four_byte_aligned_after_name`
  按预期失败，还原后全绿。
- `check` **21/21**；最终判定矩阵 **106/106 符合**，其中新增 S1 十二行全部符合。
- `fat32-probe,handles` **146/146 PASS**；`fault-rand-no-entropy` **95/95 PASS**，
  日志为 `sources=0 seeded=false block=true fill=true`，证明零熵不输出随机值。
- 固定 key/counter 的 ChaCha20 十六个字由宿主独立 RFC 8439 实现逐字对账；QEMU 正常档
  `sources=3 seeded=true`。RDRAND/RDSEED 各收集 32 字节。
- 真机、Miri、TCP ISS 消费与密码学外部审计均未验证；TSC 抖动只作为本 ADR 定义的一路熵源，
  不宣称其独立达到硬件熵源强度。
