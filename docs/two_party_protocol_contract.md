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
| Client | `A/B/C/D/x0` 明文、公开 layout/scale | `v` 明文、两份输入 share、两方资源包、两份输出 share | 无需持有 Server 的可变 state |
| P1 | `A_1/B_1/C_1/D_1/x0_1` | `v_1`、triple/mask 第 1 份、公开 Beaver `d/e`、P2 的 Protocol 2 masked 消息、`u_1` | 第二份参数/state/input/resource share，任何 controller state 明文 |
| P2 | `A_2/B_2/C_2/D_2/x0_2` | `v_2`、triple/mask 第 2 份、公开 Beaver `d/e`、`u_2` | 第一份参数/state/input/resource share，P1 的 Protocol 2 消息或 controller state 明文 |
| 单进程协调器 | 算术原语和暂态 masked 消息 | 两条 Beaver 遮蔽差值及公开 `d/e` | 参数、state、input 或 output 的明文重构结果 |

`MaskedExchangeMessage` 明确记录 P1→P2 与 P2→P1 的发送方、接收方、step 和 resource id；
`TruncationMaskedMessage` 仅允许 P2→P1。这些对象描述协议数学消息，而单进程协调器只负责
本地投递；它不是未来网络 API 的一部分。

## 离线、在线与资源

1. Client 编码并分享 `A/B/C/D/x0`，然后分别以 `OfflineControllerMessage` 发给 P1、P2。
2. 每个在线 step，Client 编码并分享 `v`，并根据 `C/D/A/B` 的每个矩阵元素生成一份独立的
   scalar Beaver triple 和一对独立的 truncation masks。
3. `StepResourcePlan` 在资源中保存 step、矩阵 shape、矩阵项索引和 fractional bits。例如状态
   维度为 `n`、输入维度为 `m`、输出维度为 `p` 时，资源数为
   `p*n + p*m + n*n + n*m`。
4. 协调器先计算 `C*x(k)+D*v(k)`，再计算 `A*x(k)+B*v(k)`，只有所有项成功才提交两方各自
   的下一 state share。因此 `u(k)` 不会错误地使用 `x(k+1)`。

当前 crypto 截断原语每个实例只有一个 `ell`，所以该协议路径只支持
`A/B/C/D/x0/v/u` 全部使用同一 `Q<ell>` 定点尺度。若 `ControllerScaleMetadata` 声明混合
尺度，Client 会在离线阶段拒绝分发，而不是静默错配乘积尺度。

每个 `ScalarResourceShare` 只能被其所属角色使用一次。两个角色均完成 Protocol 1 和
Protocol 2 后，资源标记为 `consumed`；任意校验或协议失败会把本轮尚未完成的资源标记为
`aborted`，不能在另一轮重放。固定 `random.Random(seed)` 仅用于可重复测试，正常调用不传
`rng` 时沿用 crypto 层的安全随机源。

## 声明边界与威胁模型

本实现验证的是半诚实、互不串通、存在安全信道且每次乘法/截断使用新鲜资源时的协议流程和
算术语义。它不声明进程隔离、主机隔离、网络安全、认证、抗恶意参与方或生产级端到端安全。
单进程协调路径不会把明文提供给 Server，但同一 Python 进程本身不构成隔离边界。

本 Issue 也不提供运行时 `step(v)` 包装、仿真集成、多进程或网络 transport。这些属于后续
执行层/集成工作，不能由本协议数据模型隐式替代。
