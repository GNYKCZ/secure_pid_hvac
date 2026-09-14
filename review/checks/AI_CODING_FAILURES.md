# AI-Generated Code Failure Modes — Review Checklist

本模块专门检查 AI 编程在小型 Python 仿真项目中常见、且容易“能跑但结论错”的问题。只在有具体证据时报告。

## 1. Contract / scope drift
检查：
- 用户/项目声明要求 A，代码实际验证 B；
- 一部分需求被悄悄改成“近似”“占位”“后续再做”；
- 参数/接口存在但实际未被消费；
- 文档/图标题声称的模式与运行分支不一致。

## 2. Hallucinated API / dependency facts
检查：
- 调用了当前依赖版本不存在的方法/参数；
- 根据相似库“猜”API；
- import 在开发环境偶然可用，但依赖清单未声明；
- package version 与代码使用的语义不匹配。

能从 installed package、lockfile、requirements、真实 import 验证时就验证，不凭记忆。

## 3. Partial / fake implementation
重点搜索并追踪：
- `pass`, `TODO`, `FIXME`, `NotImplementedError`；
- hard-coded return、固定零值、固定随机输出；
- placeholder branch 永远覆盖真实实现；
- demo/mock/fake 数据进入正式实验路径；
- 失败后悄悄 fallback 到 ideal/previous/zero 值。

存在标记本身不是 Bug；只有实际可达且影响声明结果时报告。

## 4. Duplicate source of truth
检查同一概念是否在多处独立写死并已经/可能漂移：
- `Ts`, horizon, gains, plant params, `ell`, `q`, seed, setpoint boundaries；
- controller matrices 与 gains 同时存在但来源不一致；
- plot 标签与实际运行配置不是同一来源。

## 5. Copy/paste branch divergence
比较 ideal / fixed-point / secure / each-ell 分支是否有非预期差异：
- 少一步 saturation/reset/update；
- 参数顺序不同；
- 使用错变量（`y_ideal` vs `y_secure`）；
- 某分支更新了 state，另一分支没有。

## 6. State lifecycle bugs
检查：
- 多次 rollout 共享旧 state/log/cache/RNG；
- shallow copy / shared mutable object 让本应独立的路径串线；
- 失败/early return 后对象保留旧 state，被下一步当作新结果；
- 初始化只在第一次运行生效。

## 7. Silent semantic failures（无异常也会错）
特别检查：
- `x or default` 把合法的 `0`, `0.0`, `False`, `""` 当缺失值；
- `.get(key, default)` / broad fallback 把缺配置变成看似正常默认值；
- `clip`, `nan_to_num`, `where`, 过滤 non-finite 数据后继续算 metric，掩盖不稳定；
- `try/except: return previous_value/0/None`；
- warnings 被全局 suppress；
- shape/squeeze/flatten 自动修正了本应暴露的维度错误。

## 8. Edge / order mistakes
检查：
- off-by-one；
- 第一个/最后一个 sample；
- `<=` vs `<` 的时间段边界；
- 先更新 state 再算本应使用旧 state 的 output；
- 循环末尾多执行/少执行一步 plant update。

## 9. Environment/path assumptions
检查：
- 依赖当前 working directory；
- Windows/Linux 路径或编码假设；
- 输出目录不存在时失败或写到错误位置；
- import-time 自动执行完整仿真导致测试/导入行为异常。

只在该项目运行方式确实可触发时报告。
