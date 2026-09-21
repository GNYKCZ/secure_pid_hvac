# 最终 HVAC 安全证据链索引

本页记录 Issue #59 使用最终快速响应 PID 生成的完整证据链。普通 `results/` 产物按仓库策略不提交
Git；下列相对路径、ID 和 SHA-256 用于在同一工作区复验，正式 PR/Issue 评论另记录最终代码提交。

## 来源身份

- start commit：`e9c8021095067e83399c11e250a83602e43e5e28`
- sweep 生成 commit：`eb24868327029ea4f9707285a3c26b859cadf4ba`，dirty=`false`
- safety 生成 commit：`ec84480e1077bb4df7c49bc5d467dd7fa35fa069`，dirty=`false`
- evidence/report 生成 commit：`b9a03185ec675fa19135093ddeda8fad80914237`，dirty=`false`
- wrapper：`configs/hvac_2r2c_dual_loop_25_20_15_fast_response.yaml`
- baseline ID：`e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7`
- ControllerSpec：`8015bd1298d25fb2dedfbe96cd1e5c5e91750a0f97980779a4520b403704f953`
- finite-horizon certificate：`9719cde72bf67a004cb2c995327cc8124142fef255add8f38c2226aaca7039ac`
- stability report：`6f7340c765e5947787fb74f726c6793d262a9bea8251843a744585a63fe512e7`

## 正式产物

| 产物 | ID / 相对路径 | SHA-256 |
|---|---|---|
| sweep | `results/sweeps/20260920T163559335539Z-7237a0665cb5/` | final manifest `bfe927e0d7e21d9739554c57f7f113c08d59a0730c4c3dc8ad5c6697fcdf59d4` |
| sweep data manifest | 同上 `data_manifest.json` | `e587119af6688914d9d435c00a566a00386b3b86d2cbffc99b32ceac17b38d53` |
| fixed-15 assumptions | `configs/hvac_2r2c_infinite_safety_25_20_15_fast_response.yaml` | `22e428032ce55a2d4a315144d3195b97848498d192357a18d42bfd71802eb0ea` |
| safety | `results/safety/20260920T170037941009Z-7e9d945e5387/` | manifest `fc654816ede3ee42a70f016dc082be5b9bde69233065b3e59a69946bdab4f51e` |
| safety certificate | 同上 `certificate.json` | `08862de749a9505edf9f07dba9f15c16cea736ff17e753fb8e83a09ba6a7fc88` |
| public evidence | `results/diagnostics/20260920T163559335539Z-7237a0665cb5/20260920T170705827260Z-f352c60ce775/` | manifest `133a45c4c66fcee5b28a03f2f8b6a41729b502513f1e561df7d670ce28180eed` |
| 中文报告 | `results/figures/evidence_reports/20260920T163559335539Z-7237a0665cb5/20260920T170810744745Z-3b61790b105c/` | report manifest `6f447f355e2008a0ea92bf789c6ddb9d43dd869fb467dd1eb1dff9f5db686e4d` |

sweep 的 final/data manifest 均通过 canonical reader；12 个点全部为 `success`。public evidence 的
180 个整数控制行和 180 个资源步骤通过严格 reader，报告 manifest 声明的 29 个图、表和目录均
逐文件通过 SHA-256 复验，并回链到同一 evidence 与 sweep。

## 四精度定量结果

每个精度的三个 seed 得到相同误差；时间为三次真实 wall-clock 的 mean ± sample std。

| ell | control max / mean / RMS (kW) | temperature max / mean / RMS (°C) | wall-clock (s) | 最大范围利用率 | Protocol 1 / 2 |
|---:|---|---|---:|---:|---:|
| 32 | `2.855852e-08 / 5.149954e-09 / 9.720291e-09` | `2.712305e-08 / 1.217113e-08 / 1.494881e-08` | `42.051170 ± 0.333913` | `0.0022013014730724867` | `1620 / 0` |
| 40 | `5.923573e-11 / 1.069159e-11 / 2.011931e-11` | `5.635314e-11 / 2.521232e-11 / 3.095761e-11` | `42.750849 ± 0.415990` | `0.0022013014730395543` | `1620 / 0` |
| 48 | `1.652012e-13 / 2.990077e-14 / 5.546514e-14` | `1.598721e-13 / 7.067926e-14 / 8.691592e-14` | `42.657750 ± 0.015870` | `0.0022013014730394532` | `1620 / 0` |
| 56 | `6.439294e-15 / 1.756620e-15 / 2.370557e-15` | `3.552714e-15 / 7.105427e-16 / 1.521181e-15` | `42.843406 ± 0.155304` | `0.0022013014730394532` | `1620 / 0` |

四个精度的最大利用率均来自 `state_payload[0]`；完整逐 seed 指标与全部范围行分别保存在
`summary.csv` 和 `range_margins.csv`。Protocol 2 为 0 是因为本 PID 的 A/B 为零分数位整数路径，
state accumulator 已处于 state scale，不需要 state Trunc；这不表示 Protocol 1、share 运算、
重构、decode、controller state 更新或 applied control 没有执行。

## fixed-15 条件定理与诊断边界

四个 `ell` 的 exact rational verifier 均返回 `certified`。结论只覆盖 reference 从证书初态起固定
为 15°C、ambient 固定为 30°C、局部初始盒、严格未饱和且扰动不超过配置界的量化闭环；不覆盖
`25→20→15°C` 的 180 步切换轨迹，也不证明一般饱和切换系统。

代表证据点为 `ell=48, seed=42, k=60`，八个正式结果字段均以 dtype、shape 和 `array_equal`
严格匹配 sweep。combined-share 仅在显式 opt-in 下短时生成，摘要为
`87bbf61363ce22fb623ff73eae38ebd3f88d87ce1b9bf5b7941d5111bfdf4413`，标记
`deployment_security=false`，未进入 public manifest 的文件闭包，并在报告闭包复验后删除。

## 复现命令

```powershell
uv run python -m secure_control.experiments.sweep_runner `
  --definition configs/hvac_2r2c_precision_sweep_definition.yaml `
  --baseline-config configs/hvac_2r2c_dual_loop_25_20_15_fast_response.yaml `
  --expected-baseline-id e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7

uv run python -m secure_control.experiments.infinite_safety_runner `
  --assumptions configs/hvac_2r2c_infinite_safety_25_20_15_fast_response.yaml `
  --sweep-dir results/sweeps/<verified-sweep-id> `
  --output-root results/safety

uv run python -m secure_control.experiments.evidence_runner `
  --source-sweep-id <verified-sweep-id> `
  --ell 48 --seed 42 --trace-step 60 `
  --baseline-config configs/hvac_2r2c_dual_loop_25_20_15_fast_response.yaml `
  --expected-baseline-id e0d0100f0ccf9fac15910c010090113574d9b53b61118fa6ad8a7035116138b7 `
  --allow-combined-share-diagnostic

uv run python -m secure_control.experiments.evidence_report_runner `
  --source-sweep-id <verified-sweep-id> `
  --trace-id <verified-trace-id> `
  --display-config configs/hvac_2r2c_evidence_report_profile_zh.yaml
```

该证据链支持“冻结 adapted 2R2C HVAC 应用在当前单进程、半诚实协议模型下可严格复现”的结论；
不支持论文原 Numerical Example 的逐项复刻、进程或主机隔离、网络安全、抗恶意安全、生产部署
安全或真实建筑标定结论。
