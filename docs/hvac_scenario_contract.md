# HVAC 场景与实验配置契约

本文冻结第一个场景的配置语义，并说明其 HVAC plant、reference 与 SignalAdapter 实现。PID 设计和
场景级明文闭环基线见 [HVAC PID 设计](hvac_pid_design.md)；通用仿真循环和任何安全协议仍未实现。
所有 HVAC 概念只属于 `secure_control.scenarios.hvac` 及其 YAML、测试和本文档。

## 基线模型与单位

配置 `model.kind: first_order_rc_cooling` 表示一阶 RC 热模型；`HvacPlant` 采用：

```text
dT/dt = (T_ambient - T) / (R C) - eta * u / C
T(k+1) = a T(k) + (1-a) T_ambient - eta R (1-a) u(k)
a = exp(-Ts / (R C))
```

- `T`、`T_ambient`：°C。
- `u`：`kW_thermal_cooling`；`u > 0` 明确表示冷却，因而在方程中降低温度。
- `R`：°C/kW；`C`：kJ/°C；因此 `R*C` 的单位为 s，和 `Ts` 一致。
- `eta`：无量纲冷却系数。
- 离散化固定为 ZOH，假设一个采样区间内 `T_ambient` 与 `u(k)` 保持常数。

`hvac_baseline.yaml` 的 `R=2.0`、`C=1200.0`、`eta=1.0`、环境/初温均为 30 °C，执行器范围为
`[0, 12] kW`。它们是可复现的仿真基线，不代表真实建筑标定参数。

## 时序、记录与 reference

`Ts=60 s`，horizon 为 `10800 s`。`terminal_sample_included: false`，所以有 180 个记录样本：
`t_k = 60k s`，`k = 0, ..., 179`；10800 s 的更新后状态不写入本次结果。

每个样本使用固定顺序：

1. 在 `t_k` 读取 `T(k)` 和 `r(k)`。
2. HVAC scenario 的 adapter 构造 `v(k) = r(k) - T(k)`；通用 simulation engine 不得计算此式。
3. controller 根据 `v(k)` 生成 `u(k)`。
4. plant 使用 `u(k)` 推进到 `T(k+1)`。
5. 记录时间 `t_k`、`r(k)`、更新前 `T(k)` 和 `u(k)`。

reference 使用左闭右开区间：`[0, 3600)` 为 15 °C，`[3600, 7200)` 为 20 °C，
`[7200, 10800)` 为 25 °C。reference API 在 `t=10800 s` 必须返回端点值 25 °C，尽管默认记录网格
不包含该时刻；其他超出 `[0, 10800]` 的时刻必须显式失败。

## 通用结果映射

HVAC 作为单输入、单输出 scenario，映射通用字段而不创建 `temperature_ideal` 等专用字段：

| 通用字段 | HVAC channel | 单位 |
| --- | --- | --- |
| `reference` | `target_temperature` | °C |
| `output_*` | `temperature` | °C |
| `control_*` | `cooling_power` | kW thermal cooling |

其中 `output_error` 是理想与安全温度输出之差，`control_error` 是理想与安全冷却功率之差；其符号由
后续通用仿真结果定义，绘图可额外显示绝对值但不得篡改原始结果。

## 已实现的场景组件

- `HvacPlant`：维护独立温度状态，`output()` 返回 `(1,)` 温度数组，`step(u)` 返回更新后的温度。
  它拒绝超出 YAML 执行器范围的控制量，而不静默裁剪。
- `HvacStepReference`：按上述边界返回 `(1,)` 目标温度；仅接受 `[0, 10800]` 内的有限时间。
- `HvacSignalAdapter`：提供通用 `ScenarioAdapter` 所需的 `reference_at` 与 `controller_input`，其中
  后者仅在 HVAC 场景中计算 `v = r - T`，并提供 YAML 冻结的通道元数据。
