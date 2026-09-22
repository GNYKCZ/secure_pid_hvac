# 通用安全状态空间运行时契约

Issue #11 在 `secure_control.execution` 中提供 `SecureStateSpaceRuntime`，让上层以与
`PlaintextStateSpaceRuntime` 相同的最小接口执行通用控制器：

```text
u(k)     = C x_c(k) + D v(k)
x_c(k+1) = A x_c(k) + B v(k)
```

输出始终读取更新前的 `x_c(k)`。runtime 只接受 `ControllerSpec`、`FixedPointContext`、
`ControllerRangeContract` 和通用输入 `v`，不解释场景、物理单位或控制器设计来源。

## 公共接口与生命周期

```python
SecureStateSpaceRuntime(
    spec,
    fixed_point,
    range_contract,
    security_parameter=...,
    test_seed=None,
)

runtime.step(v) -> ndarray(p,)
runtime.reset() -> None
runtime.spec -> ControllerSpec
runtime.scale_ledger -> ControllerScaleLedger
runtime.range_verification -> ControllerRangeVerification
```

Issue #16 另提供显式选择的 `MultiprocessingSecureStateSpaceRuntime`，保持上述 spec、输入、输出、
scale ledger、范围验证、step 和 reset 语义，并增加 `close()`、上下文管理器和只读 `topology`。
它固定使用 Windows 兼容的 `spawn` 三进程拓扑；默认 `SecureStateSpaceRuntime` 不切换后端。
超时或工作进程错误采用 fail-closed 清理，不尝试在提交状态不确定时继续。完整进程边界见
[多进程安全执行](multiprocessing_execution.md)。

Issue #17 另提供显式选择的 `LocalhostSecureStateSpaceRuntime`。它在三个 `spawn` 角色和父进程间
使用仅限 `127.0.0.1` 的固定 schema TCP 传输，仍复用同一 Protocol 3 orchestrator，并保持本节
的 spec、shape、scale、step/reset 和数值语义。网络或协议 identity 失败会关闭当前 session；
该后端不改变默认 runtime，也不声明 TLS、认证或生产安全。完整 wire 与生命周期边界见
[localhost 通信传输](localhost_transport.md)。

Issue #51 另提供可选的 `trace_policy` 与 `trace_collector`。二者必须同时给出，且只允许配合显式
`test_seed` 的诊断复现；默认均为 `None`，因此既有调用不会创建、复制或暴露 trace。启用后记录的
是实际 step 路径产生的 sanitized 证据和真实资源生命周期，不增加协议运算或 RNG 消耗。只有 policy
固定的单个 step 保存完整 controller state 更新；combined-share 审计还需要独立显式授权。

`step` 接受单输入标量、`(m,)` 扁平向量或 `(m, 1)` 单步列向量，与明文 runtime
共用同一个输入规范化函数。行向量、批量二维输入、非实数和非有限值在进入分享前被拒绝。
在符合公开范围契约的前提下，有限实数中的小数输入也合法，不由 `ControllerSpec` 的矩阵
存储 dtype 决定。明文运行时遇到整数矩阵与小数输入时保留实数运算，不把输入或更新后的
state 静默转回整数；安全运行时按 scale ledger 的 input fractional bits 编码。
输出是新建的有限 `float ndarray(p,)`。上层看不到 Client/P1/P2、share、Beaver、Trunc、
coordinator 或 controller state 明文。

一次 step 的顺序是：规范化输入、准备唯一 round、执行 Protocol 3、Client 重构输出，最后递增
step index。协议或输出重构失败时，runtime 恢复调用前的两份本地 state share、保持 step index，
关闭失败 round capability；已经消费或 abort 的资源不会复用。异常类型和原因直接向上传播。

`reset()` 在局部变量中建立全新的 Client、P1、P2、离线分发和 coordinator，全部成功后才原子
替换旧 session，并把 state 恢复为 `x0`、step 恢复为 0。失败时旧 session 保持可用。旧 session
的 capability、资源和 RNG 状态不会进入新 session。

## Scale ledger

首版要求 state/input 使用 `FixedPointContext.fractional_bits == ell`。每个字段按自己的公开
fractional bits 编码；零分数位字段必须包含数学整数，不能依赖编码取整伪装成整数矩阵。

| 值 | fractional bits |
| --- | ---: |
| state / `x0` | `state = ell` |
| input / `v` | `input = ell` |
| `A*x` | `A + state` |
| `B*v` | `B + input` |
| state accumulator | 两类 state product 的共同尺度 |
| state Trunc shift | `state_accumulator - state`，只允许 `0` 或 `ell` |
| `C*x` | `C + state` |
| `D*v` | `D + input` |
| output accumulator / Client decode | 两类 output product 的共同尺度，且不截断 |

受支持的 state 路径：

| 路径 | A/B scale | state accumulator | Trunc masks / step |
| --- | ---: | ---: | ---: |
| general fixed-point | `ell` | `2ell` | `n` |
| declared integer | `0` | `ell` | `0` |

Ax/Bv 或 Cx/Dv 尺度不一致、output 与 accumulator 不一致、state/input 不是基础 `ell`、
Trunc shift 不是 0/`ell`，均在参数分享和在线资源创建前失败。未提供
`ControllerScaleMetadata` 时保持 #10 行为：A/B/C/D/state/input 为 `ell`，output 为 `2ell`。

## 资源与范围

两条 state 路径都对每个 A/B/C/D 标量乘积使用独立 Beaver triple：

```text
triple_count = p*n + p*m + n*n + n*m
```

general fixed-point 路径对每个聚合 state 行使用一对 Trunc 辅助随机量，共 `n` 对；integer
A/B 路径为 0 对。no-Trunc 仍执行 centered `Z_q` 范围验证，仅不需要 Protocol 2 的
`Z<kappa>` 前提。公开 `ControllerRangeContract` 默认要求无限时域不变界；Issue #12 可显式
选择正整数 `horizon_steps`，使 Client 在离线阶段逐步证明有限时域 state/output 范围，并在
在线资源创建前拒绝 `step>=horizon_steps`。reset 创建的新 session 保留同一 horizon 契约。
output accumulator 在两条路径中都必须位于 centered `Z_q`。

Issue #38 增加的闭环证据模式不会改变 `step/reset`。runtime 在 session 建立时取得 Client 的
不可变 `range_verification` 摘要，包含 proof mode、证书摘要、state/output accumulator 上界、
centered modulus limit 与最大 Trunc message。Client 还会用已安装 A/B/C/D 精确重建证书声明的
仿射 composition；无关闭环问题不能只凭 controller 指纹进入该模式。`reset()` 创建新 Client 并
重新验证证据；若验证失败，旧 session 不被替换。条件和不覆盖项见
[无限时域安全契约](infinite_horizon_safety.md)。

## 数值证据与容差

`tests/test_secure_runtime.py` 使用 `ell=8` 的 generic controller-only 序列
`v=(0.1, -0.2, 0.05, 0.15)` 比较明文和安全 runtime。固定测试 seed 下实测最大 control 偏差为
`0.0015625`，验收上界为 `2 / 256 = 0.0078125`，覆盖输入量化与每个 state 行单次 Protocol 2
rounding error。整数 A/B 测试使用可精确表示输入，容差为 `1 / 256`。

## 隔离与安全声明

每个 runtime 实例拥有独立 state、Client registry、资源生命周期和 RNG。`test_seed` 只用于
transcript 相互隔离的确定性测试；安全运行必须使用默认的 `None`，由 crypto 层取得安全随机性。
session/round identity 始终由独立安全随机源生成。

默认 backend 固定为 `SingleProcessCoordinator`。Issue #16 的可选多进程 runtime 提供本机角色
进程隔离，但不声明主机隔离、网络认证、抗恶意安全或生产级端到端安全；socket 和通用网络
transport 仍不在范围内。Issue #12 仅通过场景层装配完成 HVAC 双闭环，不让 runtime 依赖 HVAC。

诊断 trace 不改变上述安全声明。公开导出不得包含 raw shares；显式 combined-share 文件只属于本地
离线审计，标记 `deployment_security=false` 并与公开 evidence manifest 物理隔离。完整发布契约见
[安全执行证据与增强中文报告](secure_execution_evidence.md)。
