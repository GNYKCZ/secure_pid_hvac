> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# 2R2C HVAC 主动 PID redesign

Issue #57 在不改变 2R2C plant、`25→20→15 °C` reference、执行器、采样周期、
horizon 或 PID realization 的前提下，增加一种显式、可重算的 plaintext controller redesign
路径。它是 adapted HVAC application 的项目设计证据，不是原论文的数值实验。

## 生成语义与 lineage

历史 `validate_current_then_conditionally_tune_v1` 仍表示兼容迁移：旧 PID 通过门禁时必须复用，
其配置 bytes、selection payload、certificate hash 和 baseline ID 均保持不变。主动 redesign 使用
独立 discriminator `plaintext_controller_redesign_v1`：实际装配并验证 source wrapper，再无条件
执行冻结 tuner。两条路径最终都归一为 `HvacPidBaselineResolution`，并进入同一个
`build_hvac_baseline_identity()` 与 `hvac_baseline_identity_v1` scheme。

```text
verified predecessor baseline
        + frozen plaintext design/quality contract
        -> deterministic exhaustive tuner
        -> canonical redesign record
        -> ControllerSpec + finite-horizon certificate
        -> hvac_baseline_identity_v1
```

新 baseline：

- wrapper：`configs/hvac_2r2c_dual_loop_25_20_15_fast_response.yaml`
- PID：`configs/hvac_2r2c_pid_baseline_25_20_15_fast_response.yaml`
- source/supersedes：`f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab`
- new baseline ID：`e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7`
- start commit：`2b173d4fb87f41941cf777af5e2fb4bda07b3b20`

lineage resolver 仅接受同目录普通非链接文件，限制递归深度并检测 cycle；前驱
wrapper/PID/scenario 在调参后重新读取，发生 TOCTOU 变化时 fail closed。

## 冻结搜索与选择

Stage 1 使用现有 10,179 点 exhaustive grid；由于存在可行候选，没有进入 Stage 2：

| gain | range | points |
| --- | --- | ---: |
| `Kp` | `-1.50 … -0.20` | 27 |
| `Ki` | `-0.00150 … -0.00010` | 29 |
| `Kd` | `-6.0 … 0.0` | 13 |

每段 hard constraints 在 objective 前过滤：settling band `±0.5 °C`、settling time
`≤900 s`、minimum signed deviation `≥-0.3 °C`、tail MAE `≤0.5 °C`、applied control
`0…12 kW`、segment saturation fraction `≤0.15`。`max MAE/max abs error/positive signed
deviation` 沿用 #53 门槛，没有放宽。

通过门禁后按以下字典序选择：maximum segment settling time、maximum segment tail MAE、
mean segment MAE、global saturation fraction，以及显式 gain tie-break。实际结果：

- evaluated：10,179；feasible：2,392；
- final gains：`Kp=-1.5`、`Ki=-0.0014`、`Kd=0.0`；
- selected objective：`(540.0, 0.032560191776974536, 0.383411569571839, 0.0, 0.0, 0.0014, 1.5, -1.5, -0.0014, 0.0)`。

secure trajectory、fixed-point error、sweep、trace 和报告数据均未参与选择。

## Plaintext old/new 指标

| segment target | old settling (s) | new settling (s) | new min deviation (°C) | new tail MAE (°C) | new max applied (kW) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 25 °C | 1140 | 540 | -0.0290683 | 0.0147663 | 7.5000 |
| 20 °C | 1140 | 540 | -0.0389458 | 0.0239045 | 9.2574 |
| 15 °C | 1080 | 540 | -0.0477616 | 0.0325602 | 10.9694 |

三个新区段 saturation fraction 均为 0。最大 settling time 从 1140 s 降至 540 s。

## Stability、安全证书与兼容验证

- closed-loop Schur status：`stable`；spectral radius `0.9993823389872556`；
- 25/20/15 °C 三个工作点均为 `applicable`；
- ControllerSpec hash：`8015bd1298d25fb2dedfbe96cd1e5c5e91750a0f97980779a4520b403704f953`；
- finite-horizon certificate hash：`9719cde72bf67a004cb2c995327cc8124142fef255add8f38c2226aaca7039ac`；
- seed 42 representative secure run 通过既有 comparison contract，最大 control/temperature
  error 分别为 `4.130970181037696e-06 kW` 与 `3.419927875114581e-06 °C`；
- 未修改 PR #56 resolver；同一 v2 definition 解析出 12 个点和 stability report hash
  `6f7340c765e5947787fb74f726c6793d262a9bea8251843a744585a63fe512e7`。

本 Issue 未运行或发布正式 12-point precision sweep、无限时域 final certificate、secure
execution evidence、报告或汇报图。这些属于后继 evidence refresh。
