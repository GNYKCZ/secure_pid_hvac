# HVAC 位置式 PID 与明文闭环基线

## PID 语义

HVAC 使用场景 adapter 产生的误差 `e(k)=r(k)-T(k)`。因为正 `u` 表示冷却，基线 gains 为负：

```text
Kp = -0.8 kW/°C
Ki = -0.0005 kW/(°C·s)
Kd = -2.0 kW·s/°C
Ts = 60 s
```

采用无滤波、导数作用于误差的位置式 PID：

```text
u_raw(k) = Kp e(k) + Ki I(k) + Kd [e(k)-e_previous(k)] / Ts
I(k+1) = I(k) + Ts e(k)
e_previous(k+1) = e(k)
```

初态为 `I(0)=0`、`e_previous(0)=0`。不使用 derivative filter；anti-windup 明确为 disabled。

## 到通用状态空间的转换

令 controller state 为 `x_c=[I, e_previous]`，则：

```text
A = [[1, 0], [0, 0]]
B = [[Ts], [1]]
C = [[Ki, -Kd/Ts]]
D = [[Kp + Kd/Ts]]
x0 = [I(0), e_previous(0)]
```

因此 `PlaintextStateSpaceRuntime` 只接收 `A/B/C/D/x0` 与 `v=e`，并不接收 PID gain object。
运行时先算 `u_raw(k)`，后更新 `x_c(k+1)`，严格对应上述公式。

## 饱和、记录与验收指标

scenario 在 `HvacPlant.step()` 前把 `u_raw` 裁剪为 `[0, 12] kW thermal cooling`，得到记录字段
`control_ideal`；`raw_control_ideal` 仅用于验证饱和位置。线性 PID state 仍按原始误差更新，故没有
anti-windup。通用 runtime 和 core 不包含这些 HVAC actuator 语义。

闭环记录 `time`、`reference`、`output_ideal`、`control_ideal`，均为通用命名字段。每个 reference
区段最后 600 s 的未过滤温度 MAE 必须不超过 1.0 °C；该阈值在运行结果前冻结于 YAML。

## 基线实测指标

在 `configs/hvac_pid_baseline.yaml` 的 180 个样本上，场景级明文闭环实际得到：

| reference 区段 | 尾部 600 s MAE |
| --- | ---: |
| `[0, 3600)` s，15 °C | 0.177410 °C |
| `[3600, 7200)` s，20 °C | 0.418147 °C |
| `[7200, 10800)` s，25 °C | 0.066011 °C |

三项均低于预设的 1.0 °C 门槛。应用到 plant 的 `control_ideal` 位于
`[0.492426, 12.0] kW`；第一步的原始 PID 输出为 12.5 kW，场景按已冻结的位置裁剪为 12.0 kW。

本场景函数保留为 #4 明文基线 oracle。Issue #12 的双闭环使用同一场景 adapter 的 actuator
hook 和通用 simulation engine，因此既有 PID gains、饱和位置和指标定义保持不变。
