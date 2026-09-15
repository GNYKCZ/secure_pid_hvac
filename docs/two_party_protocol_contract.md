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
| P1 | `A_1/B_1/C_1/D_1/x0_1`、controller session | 同一 round 的 `v_1`、triple/mask 第 1 份、公开 Beaver `d/e`、P2 的 Protocol 2 masked 消息、双尺度 `u_1` | 第二份参数/state/input/resource share，任何 controller state 明文 |
| P2 | `A_2/B_2/C_2/D_2/x0_2`、controller session | 同一 round 的 `v_2`、triple/mask 第 2 份、公开 Beaver `d/e`、双尺度 `u_2` | 第一份参数/state/input/resource share，P1 的 Protocol 2 消息或 controller state 明文 |
| 单进程协调器 | 算术原语和暂态 masked 消息 | 两条 Beaver 遮蔽差值及公开 `d/e` | 参数、state、input 或 output 的明文重构结果 |

每次离线分发都有由独立安全随机源生成的唯一 `session_id`，每个在线请求有同样生成的唯一
`round_id`；它们绝不从可重放的密码材料 RNG 派生。输入、资源计划、遮蔽消息和输出 shares 都绑定
两者。协调器会在资源 claim 前拒绝跨 session/round 拼接；Client 还登记自己签发的 distribution/round，
在输出重构前拒绝外来或未签发的完整输出对。
`MaskedExchangeMessage` 明确记录 P1→P2 与 P2→P1 的发送方、接收方、身份、step 和 resource id；
`TruncationMaskedMessage` 仅允许 P2→P1。这些对象描述协议数学消息，而单进程协调器只负责本地
投递；它不是未来网络 API 的一部分。

## 离线、在线与资源

1. Client 先用 `ControllerRangeContract` 声明编码 state/input payload 的绝对上界。它验证 `x0`
   在界内、该界对任意有界输入保持不变、每个 `A*x+B*v` 聚合行属于 `Z<kappa>`，且
   `C*x+D*v` 属于中心化 `Z_q`。无法证明这些前提的控制器在离线阶段被拒绝。
2. Client 编码并分享 `A/B/C/D/x0`，然后以同一 `session_id` 分别发送 `OfflineControllerMessage`
   给 P1、P2。每个在线 step 先验证实际 `v` 没有超出公开 input bound。
3. 每个 `A/B/C/D` 标量矩阵项消耗一个独立 Beaver triple。`StepResourcePlan` 因而需要
   `p*n + p*m + n*n + n*m` 个 triples；每个 state 元素只消耗一对独立 truncation masks，共 `n`
   对，而不是每个矩阵项一对。
4. 协调器先计算双尺度 `C*x(k)+D*v(k)`，不截断并返回给 Client；Client 按 `2^(-2ell)` 解码。
   随后协调器计算双尺度 `A*x(k)+B*v(k)`，对每个聚合 state 行恰好截断一次并提交下一 state
   shares。因此 `u(k)` 使用的是 `x(k)`，每个 state 元素仅有一个 Protocol 2 的 `w∈{-1,0,1}`。

当前 crypto 截断原语每个实例只有一个 `ell`，所以该协议路径要求 `A/B/C/D/x0/v` 使用同一
`Q<ell>` 尺度；未经截断的 output 则明确使用 `Q<2ell>`。若 `ControllerScaleMetadata` 声明
混合输入尺度，Client 会在离线阶段拒绝分发，而不是静默错配乘积尺度。

每个 `ProductResourceShare` 或 `StateTruncationResourceShare` 只能被其所属角色使用一次。两个
角色均完成对应 Protocol 1 或 Protocol 2 后，资源标记为 `consumed`；任意校验或协议失败会把
本轮尚未完成的资源标记为
`aborted`，不能在另一轮重放。固定 `random.Random(seed)` 仅用于测试：Client 会将其与本 Client
的单调 online-material epoch 作哈希域分离，所以同一 Client 重新播种同一个 seed 的多轮也不会复用
input share、triple 或 mask；不同 Client 的首轮仍可重复测试。session/round identity 始终使用独立
安全随机源，正常调用不传 `rng` 时 crypto 层同样使用安全随机源。

## 声明边界与威胁模型

本实现验证的是半诚实、互不串通、存在安全信道且每次乘法/截断使用新鲜资源时的协议流程和
算术语义。它不声明进程隔离、主机隔离、网络安全、认证、抗恶意参与方或生产级端到端安全。
单进程协调路径不会把明文提供给 Server，但同一 Python 进程本身不构成隔离边界。

本 Issue 也不提供运行时 `step(v)` 包装、仿真集成、多进程或网络 transport。这些属于后续
执行层/集成工作，不能由本协议数据模型隐式替代。
