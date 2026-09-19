# 2R2C HVAC 定点精度扫描

> 历史证据说明：本 sweep 绑定旧 15→20→25 配置链。Issue #53 不重跑 sweep，本文结果不能
> 自动视为 25→20→15 正式基线的精度证据；迁移边界见
> [hvac_reference_migration.md](hvac_reference_migration.md)。

## 冻结定义

Issue #15 在同一份 2R2C plant、位置式 PID、15 → 20 → 25 °C reference、180 步 horizon 和
`[0, 12] kW` 执行器约束上比较四种表示：

| `ell` | `k` | `k-ell` | `lambda` | seed |
|---:|---:|---:|---:|---|
| 32 | 60 | 28 | 80 | 42, 43, 44 |
| 40 | 68 | 28 | 80 | 42, 43, 44 |
| 48 | 76 | 28 | 80 | 42, 43, 44 |
| 56 | 84 | 28 | 80 | 42, 43, 44 |

全部十二点使用 `configs/hvac_2r2c_sweep_prime.yaml` 中同一个 256-bit 素数及递归
Pocklington 证据。`kappa=bit_length(q)-lambda-2=174`。seed 只控制测试用安全材料；每个 seed
建立独立 session，不能解释为生产安全随机源。seed 42 是图表主轨迹，另外两个 seed 保留运行间
分布，执行顺序固定为 ell 外层、seed 内层。

## 预检与状态

每点在建立安全 session 前执行下列门禁：

1. wrapper、PID baseline、plant 和素数证据的规范化 SHA-256 与扫描定义一致；
2. #37 的局部未饱和闭环报告仍为 Schur stable，且冻结工作点均 applicable；
3. 256-bit 模数的 Pocklington 证据由统一 crypto verifier 验证；
4. 重新计算 `kappa=bit_length(q)-lambda-2`，要求记录值一致且严格满足 `kappa > ell`；
5. 精确物化后的有限时域 input/state payload 不超过 `k` 位范围，state/output accumulator 不超过
   中心化模数范围；
6. `ell=56` 的输入 payload 上界由 binary64 的 `as_integer_ratio()` 精确有理数计算
   `ceil(abs_bound * 2^ell) + 1`，不先做可能丢低位的浮点乘法。

状态只有 `success`、`infeasible`、`failed`。不可行点不开始协议执行；运行异常或超过固定
300 s 预算的点标记失败。父进程串行启动私有单点 worker，deadline 到达后终止并回收该直接
子进程，再继续下一点；worker 只写 `work/<point>/<attempt>/`，不能发布批次或创建后代进程。
worker 在进入执行阶段前原子保存 `preflight.json`；后续异常或 timeout 沿用真实门禁与 range
margin。若场景构造尚未形成证书，则未得到的可行性结论显式保存为 `null`，不得伪造为 `false`；
该类预检拒绝记为 `infeasible`，门禁通过后的执行异常才记为 `failed`。
每点还在仿真前核对 Protocol 1/2 数量与认证整数 bit length，提升运行目录前核对字节预算。
全部点完成后，无论是否存在单点失败，扫描诊断均以同盘 rename 发布；
CLI 在存在非成功点时返回非零状态。

## 指标、成本与工件

每个成功点保存通用 schema v1 八字段轨迹、有效配置、provenance、HVAC 区段品质快照、有限时域
range margin、控制/输出误差的 max、mean、RMS、零计数和最小正 binary64 误差。`ell=56` 出现
零误差不等价于数学实数误差严格为零，因此必须同时读取 zero count 与 minimum positive value。

资源计数由实际 controller shape 和 scale ledger 精确推导：二维状态、单输入、单输出每步需要
`2*2 + 2*1 + 1*2 + 1*1 = 9` 个 Protocol 1 Beaver triples，180 步共 1620 个。位置式 PID 的
`A_c/B_c` 是精确整数，ledger 选择 state no-Trunc 路径，所以 Protocol 2 每步和总计都为 0；
禁止为获得非零数字而插入人工截断。计时从 worker 启动后的场景构造开始，覆盖预检、仿真、指标和
原始工件原子写入；最终聚合、标准图和跨点图不计入单点 wall-clock。

正式输出位于 `results/sweeps/<sweep_id>/`：

```text
definition.json
source_hashes.json
manifest.json
data_manifest.json
summary.csv
summary.json
range_margins.csv
points/<ell-seed>/config.yaml
points/<ell-seed>/record.json
standard/<ell>-<seed>/...
runs/<ell-seed>/<run_id>/{trajectory.csv,metadata.json,config.json}
figures/{control_error_vs_ell,output_error_vs_ell,control_error_over_time_by_ell,
output_error_over_time_by_ell,precision_summary,timing_cost}.png
```

父进程先发布并复验 `data_manifest.json` 覆盖的定义、逐点记录、摘要和原始运行，再由已验证 reader
生成标准图与跨精度图；主 seed 的两张时序图要求四条轨迹时间网格完全相同，log 图对真实零值使用
mask，不加入 epsilon。最后 `manifest.json` 对包含图片在内的全部文件记录 SHA-256 并再次复验。
绘图不重新运行场景或更改原始轨迹，外部 renderer 只接受最终清单；普通生成结果由 `.gitignore`
排除，不作为源码提交。

## 结论边界

该扫描复用论文的安全动态控制思想和类似 Figure 3 的精度比较方法，但 plant 参数、reference、
PID、饱和约束和实验工件属于本项目的 Adapted HVAC application。它可以支持“当前冻结场景下安全
与明文闭环一致、误差随表示精度变化”的结论，不能支持“论文原 HVAC 数值实验已逐项复刻”。由于
本控制器的整数 `A_c/B_c` 不触发 Protocol 2，本扫描也不能作为 Protocol 2 运行时行为或成本的
实证复现；Protocol 2 的正确性仍由独立的协议与算术测试覆盖。
