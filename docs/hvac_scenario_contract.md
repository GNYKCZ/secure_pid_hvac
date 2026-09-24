> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# HVAC 场景与实验配置契约

本文冻结第一个场景的配置语义，并说明其 HVAC plant、reference 与 SignalAdapter 实现。PID 设计和
场景级明文闭环基线见 [HVAC PID 设计](hvac_pid_design.md)；通用仿真循环和任何安全协议仍未实现。
所有 HVAC 概念只属于 `secure_control.scenarios.hvac` 及其 YAML、测试和本文档。

Issue #53 的当前正式 2R2C reference 为 25→20→15 °C，并保存在独立版本化 scenario 中；
旧 `hvac_2r2c_plant.yaml` 及其 15→20→25 °C reference 继续作为历史证据保留。新旧配置除
reference/endpoint 外逐字段相同，详见 [参考迁移说明](hvac_reference_migration.md)。

## 一阶历史基线模型与单位

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

## 二阶 2R2C plant-only 基线

`configs/hvac_2r2c_plant.yaml` 使用 `model.kind: second_order_2r2c_cooling` 和连续模型版本
`hvac_2r2c_no_internal_gains_v1`。状态、控制、恒定环境扰动与观测定义为：

```text
x_p = [T_air, T_wall]^T
u > 0 表示送达建筑的制冷热功率（kW thermal cooling）
d = T_ambient
y = C_p x_p = T_air,  C_p = [1, 0]

C_air  dT_air/dt  = (T_wall - T_air) / R_air_wall - eta u
C_wall dT_wall/dt = (T_air - T_wall) / R_air_wall
                      + (T_ambient - T_wall) / R_wall_outdoor
```

因此 `dx_p/dt = F x_p + G u + H T_ambient`，其中：

```text
F = [[-1/(C_air R_air_wall),             1/(C_air R_air_wall)],
     [ 1/(C_wall R_air_wall), -(1/R_air_wall + 1/R_wall_outdoor)/C_wall]]
G = [[-eta/C_air], [0]]
H = [[0], [1/(C_wall R_wall_outdoor)]]
```

配置单位统一为 `R: degC/kW`、`C: kJ/degC`、温度 `degC`、时间 `s`。由于
`kW = kJ/s`，`R*C` 的时间单位为秒。`eta=1` 是输入已经表示送达制冷热功率时的无量纲建模定义，
不是设备 COP 标定值。

### 参数来源与换算

R/C 取自 Coccia et al., *Experimental Assessment of an Air-to-Water Heat Pump Driven by a
Demand Response Strategy*（2021），Table 1，DOI
[10.18280/ti-ijes.652-413](https://doi.org/10.18280/ti-ijes.652-413)：

| 参数 | 文献原值 | 配置值 | 换算 |
| --- | --- | --- | --- |
| `C_air` | 0.40 MJ/K | 400 kJ/degC | 乘以 1000 kJ/MJ |
| `C_wall` | 48.80 MJ/K | 48800 kJ/degC | 乘以 1000 kJ/MJ |
| `R_air_wall` | 2.78e-3 K/W | 2.78 degC/kW | 乘以 1000 W/kW |
| `R_wall_outdoor` | 7.05e-3 K/W | 7.05 degC/kW | 乘以 1000 W/kW |

温差 1 K 与温差 1 degC 数值相同。该文献研究 heating 模型；本项目把输入符号适配为正 cooling。
`eta=1`、恒定环境温度 30 degC、空气/墙体初温 30 degC、`[0,12] kW` actuator 以及 reference
均为项目场景假设。特别地，12 kW 上界不是该文献的 2 kW 热泵额定值。YAML 中每个参数都以
`parameter_provenance` 保存来源类别、版本、原值、原单位、配置值和换算说明；loader 要求来源集合
与十个配置参数一一对应。

该参数集是 **literature-informed adapted benchmark**，不是实际建筑标定值，也不是 Teranishi &
Tanaka 论文中的原始 plant 数值案例。论文只给出通用离散 LTI plant 与动态控制器；这里的 2R2C
模型是安全动态控制方法的 HVAC 适配应用。

### Exact ZOH

在一个 60 s 采样周期内保持 `u` 与 `T_ambient` 常值，使用同一连续模型的增广矩阵指数：

```text
M = [[F, G, H],
     [0, 0, 0],
     [0, 0, 0]]

exp(M Ts) = [[A_p, B_p, E_p],
             [ 0,   1,   0 ],
             [ 0,   0,   1 ]]
```

不对 `F` 求逆，也不把显式 Euler 称作 exact ZOH。上述配置得到：

```text
F = [[-8.992805755395684e-04,  8.992805755395684e-04],
     [ 7.371152258521052e-06, -1.027779102145560e-05]]
G = [[-2.500000000000000e-03], [0]]
H = [[0], [2.906638762934543e-06]]

A_p = [[9.474845124536359e-01, 5.251086699334964e-02],
       [4.304169425684396e-04, 9.993952378093333e-01]]
B_p = [[-1.460256302776450e-01],
       [-3.257489875250655e-05]]
E_p = [[4.620553014539936e-06],
       [1.743452480982650e-04]]
C_p = [[1, 0]]
```

离散更新为 `x_p(k+1)=A_p x_p(k)+B_p u(k)+E_p T_ambient(k)`。采样时仍先读取
`y(k)=T_air(k)`，再施加 `u(k)` 并推进状态；负的 `B_p` 保证正制冷降低后续空气温度。
`T_wall` 只通过 `Hvac2R2CPlant.state_celsius` 的只读副本供场景测试与后续分析使用，不能成为
通用 simulation/result 的硬编码字段。

Issue #41 只冻结 plant。现有 `HvacScenario` 的一阶有限时域范围证书会明确拒绝 2R2C 配置；PID
重新整定、2R2C 明文/安全双闭环和相应范围证书属于 Issue #42，不得复用一阶公式。

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
- `Hvac2R2CPlant`：维护独立的 `[T_air,T_wall]`，但 `output()` 仍只返回 shape `(1,)` 的
  `T_air`；连续/离散矩阵和状态快照均以复制、只读形式暴露。
- `HvacStepReference`：按上述边界返回 `(1,)` 目标温度；仅接受 `[0, 10800]` 内的有限时间。
- `HvacSignalAdapter`：提供通用 `ScenarioAdapter` 所需的 `reference_at` 与 `controller_input`，其中
  后者仅在 HVAC 场景中计算 `v = r - T`，并提供 YAML 冻结的通道元数据。
