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
```

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

## 数值证据与容差

`tests/test_secure_runtime.py` 使用 `ell=8` 的 generic controller-only 序列
`v=(0.1, -0.2, 0.05, 0.15)` 比较明文和安全 runtime。固定测试 seed 下实测最大 control 偏差为
`0.0015625`，验收上界为 `2 / 256 = 0.0078125`，覆盖输入量化与每个 state 行单次 Protocol 2
rounding error。整数 A/B 测试使用可精确表示输入，容差为 `1 / 256`。

## 隔离与安全声明

每个 runtime 实例拥有独立 state、Client registry、资源生命周期和 RNG。`test_seed` 只用于
transcript 相互隔离的确定性测试；安全运行必须使用默认的 `None`，由 crypto 层取得安全随机性。
session/round identity 始终由独立安全随机源生成。

当前 backend 固定为 `SingleProcessCoordinator`。这验证协议消息流、资源生命周期与算术语义，
不声明进程/主机隔离、网络认证、抗恶意安全或生产级端到端安全。multiprocessing、socket、
transport abstraction、双 plant simulation 和任何场景集成都不属于 Issue #11；Issue #12
仅通过场景层装配完成 HVAC 双闭环，不让本 runtime 依赖 HVAC。
