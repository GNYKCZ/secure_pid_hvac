# Issue #12 领域无关仿真与 HVAC 双闭环

## 通用 step/result 契约

场景用 `Scenario.build_plan()` 返回 `SimulationPlan(metadata, sample_times, ideal, secure)`；
`simulation.runner.run(scenario)` 不导入任何具体场景，只把计划交给通用 engine。
两支各有独立 plant、adapter、runtime。每个 `t_k` 的顺序固定为：

```text
reference_at(t_k) → plant.output() → adapter.controller_input(r_k,y_k)
→ runtime.step(v_k) → adapter.apply_control(raw_u_k)
→ plant.step(applied_u_k) → 记录 r_k、更新前 y_k、applied_u_k
```

`time` 为 `(steps,)`，严格递增；其余七个字段为 `(steps,channels)`：`reference`、
`output_ideal`、`output_secure`、`control_ideal`、`control_secure`、`control_error`、
`output_error`。误差为逐时刻/逐通道的有符号 `ideal-secure`。control 只记录真正施加的
applied control，不新增 raw/PID 字段。任一 hook、分支或范围校验失败都不返回部分结果；
引擎不尝试对任意 plant/runtime 做超出当前接口的半步回滚。

## HVAC 配置、通道与公平清单

`configs/hvac_dual_loop.yaml` 仅引用 `hvac_pid_baseline.yaml`，不复制或修改 RC plant、
15→20→25 °C reference、60 s 采样、PID gains、无滤波/无 anti-windup 或 [0,12] kW
actuator。默认 10800 s 即 `t=0,60,…,10740` 共 180 个更新前样本，3600/7200 s
属于新 reference 区段。第一步 raw PID 为 12.5 kW，场景 hook 裁剪为施加的 12 kW；
线性 controller state 仍按 raw 计算顺序更新。

| 通用字段 | HVAC 通道名 | 单位 | 场景含义 |
| --- | --- | --- | --- |
| `reference` | `target_temperature` | degC | 目标温度 |
| `output_*` | `temperature` | degC | 更新前 plant 温度 |
| `control_*` | `cooling_power` | kW_thermal_cooling | plant 实际收到的冷却功率 |

公平比较采用同值不可变场景配置、同一时间网格、同一 PID `A/B/C/D/x0` 值、同一
actuator hook 和相同初温；但两支 plant、adapter、runtime state、协议 session/RNG/资源
与结果数组都独立。secure 的每次 `v` 仅由 secure plant 的当前 output 构造，完成两支
轨迹后才做误差比较。HVAC 区段尾部 600 s 温度 MAE 只在场景层解释，不进入通用八字段。

## 给定配置的 180 步有限时间证书

RC ZOH 可写为 `T_next=aT+(1-a)(T_ambient-eta R u)`，其中 `0<a<1`、`u∈[0,12]`。
从初温 30 °C 与两端平衡温度可事前得到 `T∈[6,30] °C`；reference 为 15/20/25 °C，
因此 `|v=r-T|≤19 °C`。`ell=20` 的编码上界再预留一 payload 为 `19*2^20+1 =
19,922,945`，Client 每步分享前仍检查实际 input payload。HVAC 积分态与上一误差的
公开最终 state payload 上界分别为 `180*60*19,922,945 = 215,167,806,000` 与
`19,922,945`。这不是从仿真轨迹最大值反推的证明。

配置使用素模数 `q=2^61-1`、`integer_bits=48`、`ell=20`、`horizon_steps=180`。
`ControllerScaleMetadata` 显式声明 A/B 为零分数位整数，state/input 与 C/D 为 `ell`，
output accumulator/decode 为 `2ell`；因此每步 9 份独立 Beaver triple、0 个 state
Trunc masks，180 步测试实际消费 1620 份 triples。Client 在参数分享前从编码 `x0`
逐步检查每个 state/output accumulator 的中心化 `Z_q` 前提及 state payload 界，
在线拒绝 input 超界或第 181 次 step，且拒绝发生在资源创建前。默认无限时域契约仍
拒绝该积分器；本证书只覆盖给定配置、输入/actuator 前提及 180 步，不声明无限时间
稳定、恶意安全、进程隔离或网络安全。
公开 step 必须与实际 controller state 迭代顺序一致；HVAC 集成通过 secure runtime 的
单调 step/reset 生命周期满足此前提。直接调用底层 Client/coordinator 的代码若乱序或
重复 step，不能将该 180 步证书用于额外 state 更新。

## 实际验证与运行

场景级 CLI 不选择其他场景、不保存正式 CSV/metadata 或图片：

```powershell
uv sync --locked
uv run python -m secure_control.scenarios.hvac.runner --config configs/hvac_dual_loop.yaml --seed 12
uv run pytest
uv run ruff check .
```

固定测试 seed 12 的双闭环实测最大 applied control 偏差为 `0.002148163 kW`，
最大 pre-plant output 偏差为 `0.002261731 °C`。ideal/secure 三段尾窗 MAE 分别约为
`(0.177410, 0.418147, 0.066011) °C` 与 `(0.178321, 0.418661, 0.065467) °C`。
测试 seed 只保证隔离研究复现；默认 `None` 使用安全随机材料源，不承诺按位相同。
当前 backend 仍是单进程协调器；正式结果持久化与绘图分别留给 #13/#14。
