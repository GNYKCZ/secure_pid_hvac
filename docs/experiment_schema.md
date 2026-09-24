> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# Issue #13 可复现实验产物 schema v1

Issue #71 的公开直播/回放事件使用独立版本和有损展示队列；正式八字段产物仍是无损真值。
见 [Client 公开遥测事件 v1](public_telemetry.md)。

## 入口与职责

`experiments.runner` 解析外壳 YAML 的 `scenario.name`；当前只显式选择 `hvac`，
`inverted_pendulum` 或其他未实现名称抛 `UnsupportedScenarioError`，不做动态 import。
它每次新建 `HvacScenario`，只调用一次 `simulation.runner.run(scenario)`，随后调用
场景自己的 `metrics(result)` 校验。校验成功后才由领域无关 writer 发布原始八字段；
writer/reader 不重跑控制器、不计算 HVAC/PID 算法、不绘图。

```powershell
uv run python -m secure_control.experiments.runner --config configs/hvac_dual_loop.yaml --seed 12
```

`--seed` 是安全材料的隔离测试复现模式；省略时用安全随机材料，不能声称两次随机
transcript 一样。`--output-root` 可覆盖默认的 `results/csv`，便于 Windows 空格/Unicode
路径和隔离测试。命令输出 `run_id/run_dir` 摘要，正式数据只在目录产物中。

## 身份、目录与失败语义

每次 run 生成独立的 `UTC年月日T时分秒微秒Z-12位随机nonce` 身份；即使 config/测试
seed 完全相同，两个 `run_id` 也不同，要求相同的是数值 trajectory 而非创建时间或身份。
成功目录为 `results/csv/<run_id>/`：

```text
<run_id>/
├── trajectory.csv
├── metadata.json
└── config.json
```

writer 先在同一 output root 用 exclusive `mkdir` 创建 `.incomplete-<run_id>`，它同时
充当 claim/staging；已有正式目录或同名 staging 立即拒绝，绝不默认覆盖。全部文件
exclusive 写入、flush/fsync、hash 和 reader 复验后，同文件系统 `rename` 为正式目录。
仿真/场景校验失败不创建成功目录；writer 异常只清理由本调用创建且仍位于该 root 的
staging，不删除未知用户目录。进程崩溃残留的 `.incomplete-*` 只代表不完整运行，
reader 拒绝读取，后续运行也不会自动删除它。

## CSV 和 column metadata

`trajectory.csv` 的第一列固定为 `time`（秒），其后按以下顺序写七类通用信号：

```text
reference[i], output_ideal[i], output_secure[i], control_ideal[i],
control_secure[i], control_error[i], output_error[i]
```

`i=0…channels-1`，SISO 也写 `[0]`。每个数必须能无损转为 binary64，文本用
Python `.17g`；不满足有限数值、shape、channel metadata 或 signed `ideal-secure`
误差定义时拒绝发布。`time` shape 为 `(steps,)`，其余字段读回 `(steps,channels)`，
不把任何场景的温度、功率或 raw PID 字段加入通用 CSV 列名。control 是实际施加值，
output 对应 `t_k` 的 plant 更新前测量。

`metadata.json` 保存 `schema_version=1`、`success=true`、run ID/UTC 创建时刻、
sample count、三类 channel count、场景 name/version，以及 reference/output/control 的
channel names/units、
每列的 field/index/名称/单位映射、CSV/config 的 SHA-256 与公开 provenance。
`control_error` 使用 control 单位，`output_error` 使用 output 单位。reader 验证成功
状态、版本、目录 ID、hash、header/列数/行数、shape、有限值和误差公式；缺失、损坏
或未知版本均失败，不接受 staging 或失败结果。

## 有效配置与 provenance

`config.json` 不是原始外壳 YAML 的简单复制，而是已校验、实际用于装配的
wrapper security/horizon、HVAC timing/model/reference/channels/PID、冻结策略、
执行测试 seed/随机模式及 180 步范围证书。`sources` 只存 wrapper 与 baseline 的
文件名及原始 bytes SHA-256，不含机器绝对路径；未知 YAML 字段不会被称为生效参数。

provenance 记录 project/scenario/schema version、真实 Git HEAD 与 dirty 布尔值、
`pyproject.toml`/`uv.lock` hash、项目声明的直接依赖实际版本、Python/platform、
实际配置的测试 seed 与安全材料随机模式。Git、版本或文件不可得时明确写
`available=false` 与非敏感原因；不保存用户名、环境变量、token、shares、triples、
masks 或 RNG state。相同 config/固定测试 seed 的 CSV 数值可复现，但 run ID、
创建时间、Git dirty 状态及 provenance 收集时刻不要求相同。

#12 的 HVAC 范围证书仍仅覆盖该配置及正常单调执行的 180 步，不是无限时域稳定、
密码协议主机隔离或恶意安全证明。正式产物默认由 `.gitignore` 精确忽略，不提交
普通生成 CSV；#14 绘图、#15 sweep 与进程/网络均不属于本 schema。
