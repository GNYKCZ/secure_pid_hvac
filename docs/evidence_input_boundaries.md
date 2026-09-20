# 实验证据输入边界与 schema v2 迁移

Issue #55 将“稳定实验定义、运行来源请求、解析后的 provenance、展示配置”拆成四个
生命周期不同的输入。`start_commit` 为
`58b440f32f8a57adcb141649e90f5c4b6c7ab842`；本次不运行或发布新的十二点 sweep、
infinite-horizon certificate、secure evidence 或报告。

## Coupling inventory

| 类别 | 权威输入 | 允许内容 | 禁止内容 |
|---|---|---|---|
| 稳定实验定义 | `hvac_2r2c_precision_sweep_definition.yaml` | source capability、精度/seed 矩阵、资源限制、稳定性 policy、固定 `q` 的 prime evidence | baseline 路径/ID/配置哈希、stability report hash、运行或 artifact ID |
| 运行来源请求 | `BaselineSourceRequest` | 调用者显式给出的 baseline 路径和 expected baseline ID | 搜索“最新”目录、从实际输入反读 ID 后自我确认 |
| 已解析 provenance | `ResolvedBaselineSource` / `ResolvedPrecisionSweepPlan` | actual identity scheme/ID、三源哈希、有效配置与证书摘要、实际稳定性结果、点矩阵、代码 provenance | 本机绝对路径进入 artifact |
| 展示配置 | `hvac_2r2c_evidence_report_profile_zh.yaml` | locale、单位、代表点、step、分段、图序和限制声明 | sweep/trace/run ID、baseline ID、manifest hash |
| 历史 pin | schema v1 definition/profile | 原始 source 和 artifact pins，仅供兼容核验 | 覆盖显式 v2 source 或静默升级历史文件 |

`q` 与 Pocklington 证据仍属于稳定实验定义，因为四种精度共同使用同一个模数，且它决定
`kappa` 和全部十二个点；它不是某个 HVAC baseline 的身份。

## 修改前后数据流

修改前：

```text
definition v1 = 参数矩阵 + baseline 路径/哈希 + stability hash
profile v1    = 展示语义 + sweep ID/manifest hashes
                         ↓
              runner / evidence / renderer
```

修改后：

```text
definition v2 + BaselineSourceRequest(path, expected_id)
                         ↓
      HVAC source resolver（identity + capability + trust anchors）
                         ↓
             ResolvedPrecisionSweepPlan
                         ↓
          同一 preflight / worker / publication
                         ↓
 verified sweep（definition + resolved_source + resolved_plan）

verified sweep + verified evidence + display profile v2
                         ↓
        直接核验 evidence → actual sweep lineage
                         ↓
                    同一 renderer
```

历史 v1 由薄 adapter 归一为同一个 resolved plan；不存在第二套 runner 或 renderer。

## 两个真实 baseline 的解析结果

同一 v2 definition 对两个现有来源都得到相同的 12 点矩阵。下列摘要均由实际配置链重算，
不是运行分支中的常量。

| 来源 | identity scheme | baseline ID | stability report SHA-256 | finite certificate SHA-256 |
|---|---|---|---|---|
| 历史 15→20→25 | `hvac_historical_config_chain_v1` | `2489e5476ad316ea2d9599783e29f2d849ffcf485ca860e0db76c80312c532f9` | `c6861008bf0356fb82b27ab5a5306d89f6a0095ed718706ea69a1830e9672b8d` | `063b0d344ba421bc06b0d30bd215c51abfa8ecb0a7c5a55504c6b131f257e9b8` |
| 当前 25→20→15 | `hvac_baseline_identity_v1` | `f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab` | `97eebf9ce5b67a80f52509d3e21bb1e7021979450941d1f6c628113243c39330` | `ebd7afd4b66466d29dbde897b3daad325c160ea7d4b79dbcaef48ddcaf4f794c` |

历史 `configs/hvac_2r2c_precision_sweep.yaml` 原始文件 SHA-256 保持
`87e20bf25c445849acf3ca15c8a7b6f9848f1fbd1b739aaab3cfd51a35a10e83`；历史
`configs/hvac_2r2c_evidence_report_zh.yaml` 保持
`bf3166c51ad3f87373618d2379730dbdfe0e6c7fa8178c9cb55fa0b1032cb20e`。

## CLI 与发布工件

v2 sweep 必须同时显式提供 path 和 expected ID：

```powershell
uv run python -m secure_control.experiments.sweep_runner `
  --definition configs/hvac_2r2c_precision_sweep_definition.yaml `
  --baseline-config configs/hvac_2r2c_dual_loop_25_20_15.yaml `
  --expected-baseline-id f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab
```

新 sweep 额外发布并由 data/final manifest 闭包：

```text
definition.json       # 纯稳定定义快照
resolved_source.json  # 实际 baseline identity 与配置链摘要
resolved_plan.json    # stability、prime 状态、点矩阵与代码 provenance
```

`resolved_source.json` 只记录安全单级配置名，不记录绝对路径。对 v2 sweep 重放 evidence 时，
必须再次显式提供 baseline path 和 expected ID；它们会与 verified resolved source/plan 完整核对：

```powershell
uv run python -m secure_control.experiments.evidence_runner `
  --source-sweep-id <sweep_id> --ell 48 --seed 42 --trace-step 60 `
  --baseline-config configs/hvac_2r2c_dual_loop_25_20_15.yaml `
  --expected-baseline-id f5d1bee247279ff85ba33db12778621724e46b76b880c48d8ee5637838e5aeab `
  --allow-combined-share-diagnostic
```

报告继续显式接收 verified sweep/evidence，但展示配置改用不含来源 pin 的 v2 profile：

```powershell
uv run python -m secure_control.experiments.evidence_report_runner `
  --source-sweep-id <sweep_id> --trace-id <trace_id> `
  --display-config configs/hvac_2r2c_evidence_report_profile_zh.yaml
```

## Fail-closed 与兼容边界

- v2 缺少任一 source request 字段、expected/actual ID 不同、配置链篡改、能力不兼容、
  stability/prime policy 不通过时，均在创建正式 worker/staging 前失败。
- v1 同时传入 v2 override 会被拒绝，避免双重 source authority。
- evidence v2 使用 manifest 已验证的 definition/resolved plan，并重新验证显式 baseline；不依赖
  仓库历史 definition，也不按文件名搜索来源。
- profile v2 不保存 artifact identity；renderer 直接比较 actual sweep manifest 与 evidence 中的
  source lineage，并在 rename 前重新读取全部 source/profile 摘要。
- schema v1 definition/profile 和既有 artifact reader 保持兼容，历史 bytes 不被重写。

只要未来 baseline 继续满足已声明的场景、shape、采样/horizon 和安全覆盖 contract，替换来源只需
提供新的 path/expected ID 并重新生成 downstream artifacts；通用 runner、evidence 和 renderer
不需要增加按 ID、文件名、reference 或 PID 参数的分支。
