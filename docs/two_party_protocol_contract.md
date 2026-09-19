# 通用 Client / P1 / P2 协议契约

Issue #10 在 `secure_control.protocol` 中组合既有的标量 Beaver Protocol 1 和截断
Protocol 2，以执行离散状态空间控制器的一步：

```text
x_c(k+1) = A x_c(k) + B v(k)
u(k)     = C x_c(k) + D v(k)
```

这里的 `v` 是调用方给出的通用 controller input。协议层不解释它的物理含义，也不接受场景
对象或控制器调参对象。

## 角色、可见数据和消息

| 角色 | 离线可见数据 | 在线可见数据 | 不能持有的数据 |
| --- | --- | --- | --- |
| Client | `A/B/C/D/x0` 明文、公开 layout/scale/range contract | `v` 明文、两份输入 share、两方资源包、两份输出 share | 无需持有 Server 的可变 state |
| P1 | `A_1/B_1/C_1/D_1/x0_1`、controller session | 同一 round 的 `v_1`、triple/mask 第 1 份、公开 Beaver `d/e`、P2 的 Protocol 2 masked 消息、ledger 尺度 `u_1` | 第二份参数/state/input/resource share，任何 controller state 明文 |
| P2 | `A_2/B_2/C_2/D_2/x0_2`、controller session | 同一 round 的 `v_2`、triple/mask 第 2 份、公开 Beaver `d/e`、ledger 尺度 `u_2` | 第一份参数/state/input/resource share，P1 的 Protocol 2 消息或 controller state 明文 |
| 单进程协调器 | 算术原语和暂态 masked 消息 | 两条 Beaver 遮蔽差值及公开 `d/e` | 参数、state、input 或 output 的明文重构结果 |

每次离线分发都有由独立安全随机源生成的唯一 `session_id`，每个在线请求有同样生成的唯一
`round_id`；它们绝不从可重放的密码材料 RNG 派生。输入、资源计划、遮蔽消息和输出 shares 都绑定
两者。协调器会在资源 claim 前拒绝跨 session/round 拼接；Client 还登记自己成功准备的
distribution/round 及其 output dimension，在输出重构前拒绝外来、未签发或 shape 错误的完整输出对。
每个 round 只允许成功重构一次；失败的 shape/身份校验不会提前消费合法 round capability。
`MaskedExchangeMessage` 明确记录 P1→P2 与 P2→P1 的发送方、接收方、身份、step 和 resource id；
`TruncationMaskedMessage` 仅允许 P2→P1。这些对象描述协议数学消息，而单进程协调器只负责本地
投递；它不是未来网络 API 的一部分。

## 离线、在线与资源

1. Client 先用 `ControllerRangeContract` 声明编码 state/input payload 的绝对上界。默认模式
   验证 `x0` 在界内、该界对任意有界输入保持不变、每个需 Trunc 的 `A*x+B*v` 聚合行属于
   `Z<kappa>`，且 `C*x+D*v` 属于中心化 `Z_q`。显式 `horizon_steps` 模式则从编码 `x0`
   逐步证明有限时域内的相同前提；无法证明时均在离线阶段拒绝。
2. Client 编码并分享 `A/B/C/D/x0`，然后以同一 `session_id` 分别发送 `OfflineControllerMessage`
   给 P1、P2。每个在线 step 先验证实际 `v` 没有超出公开 input bound。
3. 每个 `A/B/C/D` 标量矩阵项消耗一个独立 Beaver triple。`StepResourcePlan` 因而需要
   `p*n + p*m + n*n + n*m` 个 triples。general fixed-point A/B 路径每个 state 元素消耗一对
   独立 truncation masks，共 `n` 对；metadata 声明的 integer A/B 路径为 0 对。
4. 协调器先计算 ledger 同尺度的 `C*x(k)+D*v(k)`，不截断并按 ledger.output 返回给 Client。
   随后计算 `A*x(k)+B*v(k)`：若 accumulator 比 state 多 `ell` 位，对每个聚合 state 行恰好
   截断一次；若尺度已经等于 state，则直接提交 shares。因此 `u(k)` 使用 `x(k)`。

`ControllerScaleLedger` 冻结 state/input、A/B/C/D、两类 accumulator、Trunc shift 与 output
尺度。首版要求 state/input 为基础 `ell`，并支持 A/B 为 `ell`（state accumulator 为 `2ell`，
Trunc `ell`）或 A/B 为 0（state accumulator 为 `ell`，不 Trunc）。C/D 的乘积尺度必须相同并
直接等于 output；每个字段按自身尺度编码，零尺度字段必须是数学整数。未知 Trunc shift 或任何
待相加乘积的尺度不一致都会在分享和资源创建前被拒绝。未提供 metadata 时保持 #10 的全
`Q<ell>` operands、`Q<2ell>` output 行为。

### 有限时间范围契约（Issue #12）

`ControllerRangeContract(state_payload_bounds, input_payload_bounds, horizon_steps=None)` 的
`None` 保留 #10/#11 的无限时域不变界行为；正整数 `horizon_steps=h` 启用有限时间模式。
Client 用 Python 精确整数从每通道 `s_0=|Encode(x0)|` 递推 `k=0…h-1`：在更新前的
`s_k` 下检查 output accumulator 的中心化 `Z_q` 上界，再检查 state accumulator 的
中心化 `Z_q` 或 Protocol 2 `Z<kappa>` 前提，依据 ledger Trunc shift 推得 `s_(k+1)`，
并检查每一步 state 未越过公开 payload 界。终点 `s_h` 也被检查，但不额外运行第 `h+1`
步。在线先拒绝 `step>=h` 和超出公开范围的实际输入，再创建任何 share/triple/mask。
有限模式只声明已证明的输入界与步数内的编码安全，不声明无限时域有界或稳定性。
该有限证书还要求公开 `step` 与实际 state 迭代顺序一致；当前
`SecureStateSpaceRuntime` 用内部单调 step index、失败回滚和 reset 新 session 保证该
执行前提。直接组合 Client/coordinator 的调用方若重复或乱序提交 step，不能把此证书
误当作对那些额外 state 更新的保证。

### 闭环无限时域范围契约（Issue #38）

`horizon_steps=None` 且提供 `closed_loop_evidence` 时启用第三种
`closed_loop_invariant` 模式。Client 会在任何 share、triple 或 mask 创建前，精确复验证书
SHA-256、实际编码 controller 指纹，并把 A/B/C/D 代入内容寻址的通用仿射 composition，精确
重建 problem 的 transition、affine、disturbance 与 controller input 投影。随后才复验鲁棒正
不变椭球、controller state/input payload 投影以及全部 accumulator 数值门禁。证书为
`rejected`、`indeterminate`，或其来源、指纹、composition、投影不匹配时一律 fail closed。
该模式不改变 Protocol 1/2 消息算法；整数 A/B 的 state Trunc shift 仍为零。
完整条件和不覆盖项见 [无限时域安全契约](infinite_horizon_safety.md)。

每个 `ProductResourceShare` 或 `StateTruncationResourceShare` 只能被其所属角色使用一次。两个
角色均完成对应 Protocol 1 或 Protocol 2 后，资源标记为 `consumed`；任意校验或协议失败会把
本轮尚未完成的资源标记为
`aborted`，不能在另一轮重放。固定 `random.Random(seed)` 仅用于测试：Client 会将其与本 Client
的单调 online-material epoch 作哈希域分离，所以同一 Client 重新播种同一个 seed 的多轮也不会复用
input share、triple 或 mask；不同 Client 的首轮仍可重复测试。`rng=None` 与显式传入的
`random.SystemRandom()` 都会原样交给 crypto 层，绝不会被测试用伪随机源替换；session/round identity
始终使用独立安全随机源。

普通 `random.Random(seed)` 路径只用于隔离的确定性单元测试，不属于协议安全声明。不同 Client
若用相同 seed 创建首轮材料，必须保证 transcript 彼此隔离；任何需要沿用本页安全声明的运行都应
使用 `rng=None` 或 `random.SystemRandom()`，以保证跨 Client 的材料新鲜性。

## 声明边界与威胁模型

本实现验证的是半诚实、互不串通、存在安全信道且每次乘法/截断使用新鲜资源时的协议流程和
算术语义。它不声明进程隔离、主机隔离、网络安全、认证、抗恶意参与方或生产级端到端安全。
单进程协调路径不会把明文提供给 Server，但同一 Python 进程本身不构成隔离边界。

Issue #11 已在 execution 层提供运行时 `step(v)` 包装；Issue #12 的 HVAC 仿真集成只使用
公开有限时间范围契约，不改变本协议消息算法。多进程和网络 transport 仍不属于本协议
数据模型。运行时契约见 [通用安全状态空间运行时](secure_runtime_contract.md)。
