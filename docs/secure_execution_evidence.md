> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# 安全执行证据与增强中文报告

> 历史 schema v1 证据仍绑定旧 15→20→25 sweep，不能自动外推。Issue #59 已用最终快速响应
> `25→20→15°C` baseline 生成新的 schema v2 证据链；具体 ID、哈希和结果见
> [最终 HVAC 安全证据链索引](final_hvac_evidence_chain.md)。

Issue #55 的 v2 evidence 路径改用 verified sweep 内的 resolved plan，并要求显式 baseline
path/expected ID；v2 展示 profile 不再复制 sweep/manifest 身份。迁移说明见
[实验证据输入边界与 schema v2 迁移](evidence_input_boundaries.md)。

## 目的与边界

Issue #51 为冻结的 2R2C HVAC 精度扫描增加一条显式、默认关闭的诊断路径。它记录真实
`SecureStateSpaceRuntime` 执行中的编码整数、Protocol 1/2 资源生命周期、Client 重构、decode、
controller state 更新和 actuator 后的 applied control；不会用展示层重新计算协议结果，也不会
改变正式八字段结果 schema。

诊断使用固定 `test_seed`，因此只适用于可复现性验证。combined-share 文件仅在命令行显式授权后
写入 `results/diagnostics/private/<trace_id>/`，标记 `deployment_security=false`，不进入公开 evidence
manifest，也不代表部署中的任一参与方可以同时取得两份 share。公开工件只保留重构结论、资源 ID
不可逆摘要和无损十进制整数。

## 固定复现入口

以下命令只复现冻结 sweep 中的 `(ell=48, seed=42)` 成功点，并在 `k=60` 保存完整状态证据：

```powershell
uv run python -m secure_control.experiments.evidence_runner `
  --source-sweep-id <verified-sweep-id> `
  --ell 48 --seed 42 --trace-step 60 `
  --baseline-config configs/hvac_2r2c_dual_loop_25_20_15_fast_response.yaml `
  --expected-baseline-id e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7 `
  --allow-combined-share-diagnostic
```

schema v2 必须显式传入 `--baseline-config` 与 `--expected-baseline-id`，并与 manifest 已验证的
`resolved_source.json`/`resolved_plan.json` 一致；不会回退到仓库历史 definition 或自动选择
来源。历史 schema v1 命令仍可省略这两个参数。

发布前会用 canonical sweep reader 复验来源，并对 `time/reference/output_ideal/output_secure/`
`control_ideal/control_secure/control_error/output_error` 同时检查 dtype、shape 与 `array_equal`。任一字段
不严格相等、来源 bytes 在运行期间变化、180 个 step 不连续、资源累计与正式 summary 不一致，都会
拒绝发布。

公开目录 `results/diagnostics/<sweep_id>/<trace_id>/` 包含：

- `integer_control.csv`：逐 step 的 raw 明文/安全控制、residue、centered integer、scale、applied control；
- `resource_counts.csv`：真实创建/消费/废弃累计数、逐步增量及 A/B/C/D/state truncation 分解；
- `selected_step_trace.json`：固定 step 的输入、输出与 controller state 更新证据，不含 raw shares；
- `metadata.json` 与 `manifest.json`：来源、模数 `q`、严格等价结论、随机性声明、private audit 摘要及文件哈希闭包。reader 会按 `q` 验证每个 canonical residue 与 centered integer 的映射，并拒绝公开目录中的任何未声明目录、嵌套文件或链接成员。

大整数以十进制文本保存，不经 JSON binary64。删除 private combined-share 文件后，公开 reader 仍可
独立复验 sanitized evidence。

## 增强报告

增强报告只组合 `load_verified_sweep_data()` 与 `load_verified_evidence_artifacts()` 的返回值，不导入
场景、runtime 或诊断 runner，也不会重跑仿真：

```powershell
uv run python -m secure_control.experiments.evidence_report_runner `
  --source-sweep-id <verified-sweep-id> `
  --trace-id <trace_id> `
  --display-config configs/hvac_2r2c_evidence_report_profile_zh.yaml
```

输出位于 `results/figures/evidence_reports/<sweep_id>/<report_id>/`。主汇报依次展示双路径、选定 step、
整数/decode/applied 对应、状态更新、分钟轴闭环结果、applied-control Fig. 3 adapted、无量纲精度影响、
四精度定量表与协议资源/实测时间。附录保留 Issue #48 的十二类图、raw-control 数值诊断图，以及
`[0,60)`、`[60,120)`、`[120,180)` 三个无重复无遗漏的分钟分段。

整数图中的完整轨迹直接读取 `integer_control.csv` 的 180 个 centered integer，并用 marker 强调每个
离散 secure step；折线只辅助观察。图内固定列出 `k=58..62` 的原始十进制整数，并从真实
`ControllerScaleLedger.output` 展示 `û_raw=m_centered/2^ell_out`。当前代表点 `ell_out=96`，`k=60`
继续与单步 trace 的 residue、centered integer、raw decode 和 applied control 交叉核对。纵轴若使用
十进制显示缩放，只作用于绘图副本，不修改或替代 artifact 中的精确整数。

Fig. 3 adapted 只使用正式八字段中的 applied control error；raw control error 单列为数值机制诊断。
报告中的 wall-clock 是三 seed 的实测 mean ± sample std，协议资源是跨 seed 完全相等后才展示的 exact
计数；代表点资源子图还直接展示 180 步实际累计消费与逐步增量。报告 manifest 绑定两个来源
manifest、两个展示 profile、字体和全部输出哈希。

## exact-grid sidecar 与 binary64 零碰撞

Issue #62 不修改八字段 trajectory，也不从已 decode 的 secure float 反推整数。薄入口只消费已经通过
canonical reader 的 sweep 与 `integer_control.csv`，并要求显式传入 sweep final/data manifest 的预期
SHA-256：

```powershell
uv run python -m secure_control.experiments.exact_grid_runner `
  --source-sweep-id <verified-sweep-id> `
  --evidence-dir <verified-evidence-directory> `
  --source-manifest-sha256 <final-manifest-sha256> `
  --source-data-manifest-sha256 <data-manifest-sha256>
```

发布前逐 step、逐 channel 证明 `raw_plaintext == applied_plaintext` 且
`raw_secure == applied_secure`，并复验时间、applied control、error、run ID、trajectory hash 与 evidence
lineage；actuator 不是恒等映射时 fail closed。sidecar 对 ideal applied binary64 值 `x` 使用
`M=floor(Fraction.from_float(x)·2^s+1/2)`，直接读取 secure centered integer `U`，保存无损十进制
`M`、`U`、`Δ=M-U` 与 `s`（CSV 中分别为 `ideal_grid_integer`、`secure_grid_integer`、
`signed_error_integer`、`output_fractional_bits`）。这里的 exact-grid error 是 `Δ/2^s`；它不同于未量化的
`Fraction.from_float(x)-U/2^s`，二者都不是“无限精度理论真值”。

分类规则固定为：`Δ=0` 是 `exact_grid_zero`；binary64 applied error 为零而 `Δ!=0` 是
`float64_collision`；其余是 `nonzero`。原有 `zero_count` 数值与语义不变，sidecar 摘要将其明确命名为
`float64_zero_count`。报告只有在显式传入 `--exact-grid-dir` 时才增加第二个 exact-grid panel；原有四条
binary64 曲线和零 mask 保持不变，不插入 epsilon。缺少整数证据的精度明确显示为 unavailable，绝不
补算或隐式重跑 evidence。

## Protocol 2 为零的含义

当前冻结 PID 的 `A/B` 是零分数位整数矩阵，state accumulator 已处于 state scale，因此正式路径不需
执行 state Trunc，180 步的 Protocol 2 count 为 0。这不影响本次双闭环数值复现：严格八字段比较、
Protocol 1、重构、decode、state 更新和 applied control 都已实际执行。它也不证明 Protocol 2 在完整
HVAC 闭环中的行为；Protocol 2 正负数、边界与允许误差语义由独立通用测试覆盖。

本报告支持“冻结 adapted HVAC 应用在当前单进程、半诚实协议模型下可严格复现”的结论，不支持论文
原 Numerical Example 的逐项复刻、进程/主机隔离、网络安全、抗恶意安全或真实建筑标定结论。
