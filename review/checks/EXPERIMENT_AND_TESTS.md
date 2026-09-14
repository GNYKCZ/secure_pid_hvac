# Experiment, Results, Tests, and Claims Review

## Experiment isolation / reset
检查每个 `ell`、seed、重复实验是否重新初始化：
- plant state；
- controller state；
- secret-shared state；
- logs/buffers；
- counters/masks/triples；
- RNG state（按项目声明的复现策略）。

不要仅看到 `reset()` 名字就认定正确；追读它实际清理的字段。

## Data provenance
从 plot/metric 反向追到生成它的 rollout：
- `u_ideal` 与 `u_secure` 来自同一 run / same config；
- temperature/error 数组没有被旧文件、旧 ell、最后一次循环或缓存覆盖；
- saved filename/metadata 与内容一致；
- 横轴、legend、单位、ell 标签和真实数据一致。

## Metric integrity
- `abs(u_ideal-u_secure)` 是否逐时刻对齐；
- RMSE/max 等 metric 没有漏掉 NaN/Inf 后“变好”；
- clip/smooth/downsample 只用于展示时不应修改用于结论的原始 metric；
- log scale 对 0 的显示处理没有反写数据；
- 多个 ell 的比较使用一致 horizon / initial state / plant/controller config。

## Behavioral tests
检查现有 tests 是否真正覆盖行为而不是只覆盖代码行：
- assertion 是否会在实现错误时失败；
- expected value 是否独立于被测实现，而不是用同一公式算一遍；
- mock 是否绕过真正关键路径；
- tolerance 是否大到错误实现也能通过；
- `skip/xfail` 是否把关键失败隐藏；
- tests 是否真的被 test runner 收集和执行；
- negative/edge cases 是否覆盖最关键的边界（时间切换、负数 modulo、Trunc、reset 等）。

## Test tampering / false green
在 Diff Mode 特别检查：
- 删除/弱化 assertion；
- 无依据扩大 tolerance；
- 直接更新 expected/snapshot 来追随错误输出；
- production 分支专门识别 test environment；
- test fixture 被固定成永远绕过新逻辑。

## Claim consistency
逐条比较：代码、README/报告文字、图标题、论文对应、实际验证证据。
只有代码和运行证据支持的 claim 才能被判为成立。

特别区分：
- “参考论文方法的 HVAC adaptation” vs “复现论文原数值例”；
- “local two-party protocol emulation” vs “真实双云部署”；
- “本次轨迹误差很小” vs “理论上对所有时间/参数都满足 bound”。
