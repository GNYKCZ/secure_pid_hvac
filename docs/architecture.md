# 场景无关架构基线

## 目标

`secure_control` 为多个动态控制场景提供共享基础。HVAC 是第一个场景；未来加入其他场景时，
设计目标是主要新增 `scenarios/<name>/`、对应配置和场景测试。

## 模块职责与依赖

```text
experiments ─→ scenarios / simulation
scenarios ──→ simulation / execution / core
simulation ─→ execution / core
execution ──→ protocol / core
protocol ───→ crypto / core
crypto ─────→ 标准库和纯数值依赖
core ───────→ 标准库和基础数组类型
```

- `core` 只定义通用控制数据，如 `ControllerSpec(A, B, C, D, x0)`。
- `crypto` 只处理整数、向量/矩阵、定点 scale、模数、公开素数证据、share 和辅助随机量。
- `protocol` 只编排通用控制器参数、状态、输入和输出的 shares。
- `execution` 向上提供统一的 `step(v) -> u` 接口，具体 transport 不改变该接口。
- `simulation` 只协调 reference、plant output、scenario adapter、runtime 和结果记录。
- `scenarios` 拥有 plant、reference、controller design、信号适配、单位和场景指标。
- `experiments` 是独立 I/O/composition root：显式场景选择、通用结果产物与公开 provenance；
  已保存结果的绘图也在此层从正式 reader 获取数据，不参与 engine 的控制循环，
  不把场景算法加入通用 writer/plotting。

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
controller design 负责在进入 runtime 前生成这些矩阵。

若使用定点表示，`ControllerScaleMetadata` 分别记录 state（亦即 `x0`）、input、output、
`A/B/C/D` 的 fractional bits。它只是数值表示元数据；编码、模运算和 truncation 仍由后续
`crypto` 与 `protocol` 工作实现。

`PlaintextStateSpaceRuntime` 是第一个运行时实现。对每个输入 `v(k)`，它先计算
`u(k) = Cx_c(k) + Dv(k)`，再计算 `x_c(k+1) = Ax_c(k) + Bv(k)`；因此控制输出使用更新前
状态。状态、输入和输出维数由 `A/B/C/D` 的兼容 shape 决定，`n`、`m`、`p` 均不限制为 1。
运行时接受标量（仅单输入）、长度为 `m` 的扁平输入数组 `(m,)`，以及论文中常用的单步列向量
`(m, 1)`；列向量只会在内部归一化为 `(m,)`，这只是 NumPy 单步表示约定，不改变控制器维数。
行向量和批量二维输入没有定义为单步接口的一部分，必须被拒绝。运行时始终返回长度为 `p` 的
扁平 control vector `(p,)`，计算失败不会写入半完成的 controller state。

`SecureStateSpaceRuntime` 实现相同的 `ControllerRuntime` 契约，内部封装 Client/P1/P2、
一次性 Beaver/Trunc 资源与当前单进程 coordinator。它依据公开 scale metadata 选择 general
fixed-point A/B 的逐聚合 state 行 Trunc，或 integer A/B 的 no-Trunc 路径；选择不依赖场景或
控制器类型。失败 step 回滚 state share 且不推进 step，reset 通过新建 session 恢复 x0。
具体尺度、资源和安全边界见[安全运行时契约](secure_runtime_contract.md)。

依赖素数域前提的 Protocol 2 统一调用 `crypto.primes`。该模块对 64 位范围执行确定性 MR64，
对更大模数只接受本地可复核的递归 Pocklington 证据；它不读取 YAML 或访问网络。证据只沿
`scenario -> execution -> protocol -> crypto` 单向传递，场景层仅映射配置 schema，不能复制
数论验证。一般 `TwoPartySharing` 仍表示通用模环，不因截断的素数前提而改变构造契约。

## 场景与仿真契约

场景通过 `Scenario.build_plan()` 事前装配通用 `SimulationPlan(metadata, sample_times,
ideal, secure)`，两支 `SimulationBranch` 各持有独立 plant/adapter/runtime。场景自己的
`ScenarioAdapter` 提供 reference，将本支 plant output 映射为 controller input `v`，并将
raw controller output 映射为实际送给 plant 的 applied control。仿真引擎不得假设 `v`
一定是两个信号的差值，也不得在通用层解释 actuator 单位。

`simulation.runner.run(scenario)` 只取得计划并调用 `engine.compare_closed_loops`，不选择
HVAC 或导入任何场景/协议实现。每支按 reference→更新前 output→adapter 的 `v`→
runtime 的 raw control→场景 actuator→plant.step 顺序执行；记录的 output 对应更新前
时刻，control 对应 applied control。两支完成后逐时刻计算有符号 `ideal-secure` 误差。
时间必须有限且严格递增；共享可变 plant/adapter/runtime、非有限信号、通道错位或任一
分支失败均不返回部分 `SimulationResult`。

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

HVAC 的装配与 180 步物理/编码范围条件见 [仿真与双闭环集成](simulation_hvac_integration.md)。
正式场景选择、schema v1 与无覆盖发布见 [实验产物约定](experiment_schema.md)。
从已发布结果生成四类图、显式向量通道选择与 log 零值规则见
[已保存结果绘图契约](figure_contract.md)。
