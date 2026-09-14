# 场景无关架构基线

## 目标

`secure_control` 为多个动态控制场景提供共享基础。HVAC 是第一个场景；未来加入其他场景时，
设计目标是主要新增 `scenarios/<name>/`、对应配置和场景测试。

## 模块职责与依赖

```text
scenarios ──→ simulation / execution / core
simulation ─→ execution / core
execution ──→ protocol / core
protocol ───→ crypto / core
crypto ─────→ 标准库和纯数值依赖
core ───────→ 标准库和基础数组类型
```

- `core` 只定义通用控制数据，如 `ControllerSpec(A, B, C, D, x0)`。
- `crypto` 只处理整数、向量/矩阵、定点 scale、模数、share 和辅助随机量。
- `protocol` 只编排通用控制器参数、状态、输入和输出的 shares。
- `execution` 向上提供统一的 `step(v) -> u` 接口，具体 transport 不改变该接口。
- `simulation` 只协调 reference、plant output、scenario adapter、runtime 和结果记录。
- `scenarios` 拥有 plant、reference、controller design、信号适配、单位和场景指标。

低层模块不得反向导入 `scenarios`。具体场景名称、单位或控制器调参字段不得进入
`core`、`crypto`、`protocol`、`execution` 或 `simulation`。

## 通用控制器契约

控制器使用离散状态空间形式：

```text
x_c(k+1) = A x_c(k) + B v(k)
u(k)     = C x_c(k) + D v(k)
```

`ControllerSpec` 只保存 `A/B/C/D/x0` 及必要的 shape、dtype、scale 元数据。零维 controller state
是合法的，因此静态状态反馈可直接表示为 `u = Dv`，无需人为引入无意义的内部状态。场景中的
controller design 负责在进入 runtime 前生成这些矩阵。实际递推算法不属于当前架构基线。

若使用定点表示，`ControllerScaleMetadata` 分别记录 state（亦即 `x0`）、input、output、
`A/B/C/D` 的 fractional bits。它只是数值表示元数据；编码、模运算和 truncation 仍由后续
`crypto` 与 `protocol` 工作实现。

## 场景与仿真契约

场景通过 `ScenarioAdapter` 提供 reference，并将 reference 与 plant output 映射为 controller input
`v`。仿真引擎不得假设 `v` 一定是两个信号的差值。

结果统一记录：

```text
time
reference
output_ideal
output_secure
control_ideal
control_secure
control_error
output_error
```

每个 signal 使用 `(sample_count, channel_count)` 表示，因此标量与向量输出遵循同一契约。
场景通过 `ScenarioMetadata` 解释 channel name 和 unit。

配置至少包含：

```yaml
scenario:
  name: <scenario-name>
```

本文件只冻结职责边界，不实现具体场景、控制器、安全算术或协议。
