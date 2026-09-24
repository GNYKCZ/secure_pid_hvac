> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# 2R2C HVAC 25→20→15 正式参考迁移

## 迁移边界

Issue #53 将正式 2R2C HVAC 参考轨迹迁移为 25→20→15 °C，每段 3600 s，采样周期
60 s，共 180 步。新配置链为：

```text
hvac_2r2c_dual_loop_25_20_15.yaml
  → hvac_2r2c_pid_baseline_25_20_15.yaml
  → hvac_2r2c_scenario_25_20_15.yaml
```

除 reference 外，连续 2R2C 方程及 exact-ZOH 离散化、30 °C 空气/墙体初态、30 °C
环境温度、正制冷方向、`[0, 12] kW` 执行器、60 s 采样、180 步 horizon 和 PID realization
均保持不变。旧配置没有被覆盖；它们以及基于 15→20→25 的稳定性、精度扫描、图表和安全
执行证据均保留为历史证据，不自动外推到新正式基线。

## PID 选择门禁

迁移严格执行 `validate_current_then_conditionally_tune_v1`：先在新 reference 上仅运行 plaintext
闭环验证 Issue #42 的 PID；只有门禁失败时，才运行 Issue #42 冻结的 10,179 点 exhaustive grid。
当前 `Kp=-0.85`、`Ki=-0.0007`、`Kd=-0.5` 在三个区段均通过，因此：

- `pid_reused=true`；
- `tuning_executed=false`；
- `search_space_candidate_count=10179`；
- `evaluated_candidate_count=0`。

这里的 0 表示网格搜索没有必要执行，不表示没有验证 PID。完整明文门禁指标、旧/最终 gains、
品质契约摘要和选择记录均冻结在新 PID YAML，并在运行时重算核对；声明被修改时 fail closed。

plaintext 门禁的三个区段 MAE 分别为 `0.699426`、`0.690107`、`0.680037 °C`，tail MAE
分别为 `0.009251`、`0.007583`、`0.024846 °C`；全程饱和占比为 0，最大 applied control
为 `7.773937 kW`。这些值来自同一闭环重算，不是为了通过门槛而写入的替代数据。

## 身份与 lineage

新基线使用 `hvac_baseline_identity_v1`。`baseline_id` 绑定规范化后的 wrapper/PID/scenario
来源摘要、品质契约、实际 PID 选择记录、通用 `ControllerSpec` 和 180 步有限时域证书。
测试 seed、run ID、时间戳和本机绝对路径不参与身份，因此同一内容在不同运行间保持稳定。

`start_commit=a1561d0800127e35f263cf6afd0213d4d7563a3a` 记录迁移开始点；
`supersedes_baseline=2489e5476ad316ea2d9599783e29f2d849ffcf485ca860e0db76c80312c532f9`
是旧三配置链的规范内容身份。loader 会验证旧 wrapper 摘要及其 PID 引用，再结合旧 PID 和 scenario
的 canonical hashes 重算该身份；任一来源漂移或伪造 predecessor 都会 fail closed。新 wrapper
也以 canonical SHA-256 固定其 PID baseline。两者作为 lineage 与新 `baseline_id` 并列记录，
不混入可变运行信息。

当前冻结摘要为：

```text
baseline_id                       f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab
quality_contract_sha256           a7cbc38beb93556d0e073a796d455cc6adce57e17ec94d9dffd1eeb9b7d31a83
selection_record_sha256           9f965a4ed4147abcc88e3e8ae2c5727886adc1b9645e877866db04b291246897
controller_spec_sha256            f15604f828c3a53b1b2f5a45c3f845c88a399c2998f6b3e3a2a23c5e0eef1aeb
finite_horizon_certificate_sha256 ebd7afd4b66466d29dbde897b3daad325c160ea7d4b79dbcaef48ddcaf4f794c
```

新 reference 下先验 controller input 界为 `[-15.0, 27.356822440223024] °C`，raw control
界为 `[-173.1173945137133, 88.01497266600526] kW`；编码 input/state payload 界分别为
`(28685709,)` 与 `(309805657200, 28685709)`，最大 output accumulator 界为
`(252202630785534,)`，低于 centered modulus limit `1152921504606846975`。这些界来自完整
actuator box 的 180 步先验传播，不是观测轨迹最大值；第 181 次 controller update 仍被拒绝。

## 运行与结论边界

```powershell
uv run python -m secure_control.scenarios.hvac.runner --config configs/hvac_2r2c_dual_loop_25_20_15.yaml --seed 42
uv run python -m secure_control.experiments.runner --config configs/hvac_2r2c_dual_loop_25_20_15.yaml --seed 42
```

正式产物仍使用既有通用八字段 schema；新增身份和 PID 选择记录只位于 effective config。
本迁移重建 plaintext/secure 代表运行与 180 步证书，但不重跑精度 sweep、稳定性/不变集证明、
中文报告或安全执行证据。该结果仍是 adapted application，不是论文原数值实验或真实建筑标定。

seed 42 的诊断重跑已证明启用现有内存 trace 不改变正式八字段。ideal/secure 的 max applied
control error 为 `3.378811e-6 kW`，max pre-plant output error 为 `4.730292e-6 °C`，均通过
冻结比较门槛。raw ideal/secure control 范围分别为 `[1.764799401, 7.773937279] kW` 与
`[1.764799008, 7.773938459] kW`，最大 raw 差为 `3.378811e-6 kW`；本次 raw 均未触发饱和，
所以对应样本的 raw 与 applied 相同。raw 只用于默认关闭的诊断核查，没有写入 trajectory schema。
