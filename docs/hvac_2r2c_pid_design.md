# 2R2C HVAC PID 调参与双闭环基线

## 适用边界

本基线把项目的 2R2C HVAC plant、15→20→25 °C reference、执行器饱和和位置式 PID
作为论文通用动态控制器与安全计算协议的 **adapted application**。它不是论文 Sec. VII 的原数值
实验复刻。本文只声明 180 个采样步的有限时域范围与数值比较，不声明闭环 Schur 稳定、无限时域
不变性、真实建筑标定或生产安全等级。

权威配置链为：

```text
hvac_2r2c_dual_loop.yaml
  → hvac_2r2c_pid_baseline.yaml
  → hvac_2r2c_plant.yaml
```

PID 配置保存按 LF 规范化的跨平台 plant SHA-256，正式 effective config 同时保存 wrapper、PID baseline 与 plant
三个源文件的 SHA-256。`T_wall` 始终是 HVAC plant 内部状态，正式八字段结果只公开 `T_air`。

## 冻结调参协议

调参只运行 plaintext 2R2C 闭环，不接受 secure runtime、协议结果或随机 seed。搜索采用
`deterministic_exhaustive_grid_v1`，三轴均由端点和点数生成：

| gain | 范围 | 点数 |
| --- | --- | ---: |
| `Kp` | `[-1.50, -0.20]` | 27 |
| `Ki` | `[-0.00150, -0.00010]` | 29 |
| `Kd` | `[-6.0, 0.0]` | 13 |

候选按 `Kp → Ki → Kd` 升序笛卡尔积遍历，共 10,179 个。可行性门槛、600 s tail window、
±0.5 °C 持续调节带、饱和容差及三个 reference 区段的全部阈值均冻结在 PID YAML 中。
可行候选依次最小化：最大区段 tail MAE、区段 MAE 平均值、全程饱和占比、`|Kd|`、
`|Ki|`、`|Kp|`，最后按 `(Kp, Ki, Kd)` 唯一决胜。

正式重跑评估 10,179 个候选，其中 679 个可行，得到：

```text
Kp = -0.85 kW/°C
Ki = -0.0007 kW/(°C·s)
Kd = -0.5 kW·s/°C
objective = (0.0597207712547501, 1.1932930117280225, 0.03333333333333333,
             0.5, 0.0007, 0.85, -0.85, -0.0007, -0.5)
```

PID realization 仍为 `x_c=[I,e_previous]`，输出使用更新前状态；不增加 derivative filter 或
anti-windup。执行器只在 plant 前把 raw control 裁剪到 `[0,12] kW`，积分态不会跟踪饱和，
因此 windup 仍是本基线的明确限制。

## 控制品质与安全比较

明文分支的三个区段结果为：

| 区段目标 | MAE (°C) | tail MAE (°C) | 最大绝对误差 (°C) | 调节时间 (s) | 饱和占比 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 15 °C | 2.099764 | 0.022305 | 15.000000 | 1680 | 0.016667 |
| 20 °C | 0.736315 | 0.059721 | 4.999149 | 1140 | 0 |
| 25 °C | 0.743800 | 0.030023 | 5.052894 | 1140 | 0.083333 |

固定测试 seed 只复现协议材料，不参与调参。一个正式 180 步双闭环运行得到：

- `max/mean/RMS |u-û|`：`9.15033e-06 / 1.91268e-06 / 2.88145e-06 kW`；
- `max/mean/RMS |T_air-T̂_air|`：`1.25049e-05 / 4.39959e-06 / 5.53053e-06 °C`；
- ideal、secure 两支均通过同一控制品质门槛。

调节时间从当前区段起点计时，且要求此后持续处于带内直到区段结束；未达到时保存为 `None`
并判失败，而不是用区段终点代替。

## 180 步有限时域证书

场景用 2R2C exact-ZOH `A_p/B_p/E_p` 和完整执行器区间逐步传播 `T_air/T_wall`，再逐步传播
`e`、`I/e_previous` 与 raw control。对当前配置，保守全时域物理界为：

```text
T_air  ∈ [-5.4254880184, 30.0] °C
T_wall ∈ [27.6680777338, 30.0] °C
e      ∈ [-15.0, 30.4111080710] °C
I      ∈ [-108000.0, 223328.7523] °C·s
u_raw  ∈ [-181.1973945137, 79.9349726660] kW
u      ∈ [0.0, 12.0] kW
```

这些是先验盒区间，不是观测轨迹。场景再用论文对应的 fixed-point rounding 生成 input/state
payload 界，以 Python 精确整数计算每步 state/output accumulator 上界，并把同一范围交给
`ControllerRangeContract(horizon_steps=180)`。当前 PID 的 `A/B` 为整数，scale ledger 明确给出
`state_truncation_bits=0`；这个结论只适用于当前 realization。第 181 次 controller step 会被拒绝。

当前 `lambda=8`、61-bit 模数、semi-honest/non-colluding 和单进程实现仅为研究/测试 baseline，
不能表述为生产部署安全性。
