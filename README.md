# secure_pid_hvac

本项目用于研究论文 *Client-Aided Secure Two-Party Computation of Dynamic Controllers*
中的两方安全动态控制思想。第一个实验场景是 HVAC + PID；未来计划加入 Inverted Pendulum
等场景，并复用同一套控制器规格、安全算术、两方协议、执行层和仿真基础设施。

GitHub 仓库和发行包继续使用 `secure_pid_hvac` / `secure-pid-hvac`，Python 导入包使用更通用的
`secure_control`。HVAC 是第一个场景，不是核心领域；它的模型、参考轨迹、PID 设计、信号适配、
单位和指标应集中在 `secure_control.scenarios.hvac`。

当前已完成架构基础、一阶与 2R2C HVAC 明文基线、安全算术原语与组合验证门、通用
Client/P1/P2 单进程协议核心、与明文接口兼容的通用安全状态空间运行时，以及领域无关 simulation engine 和
180 步 HVAC 明文/安全双闭环。尚未实现 multiprocessing 或网络通信。
现已提供显式场景选择的实验入口与通用 CSV/metadata/config 产物。

## 架构边界

- `core`：通用离散状态空间控制器规格 `A/B/C/D/x0`。
- `crypto`：领域无关的定点数、模运算和安全算术；不得依赖场景。
- `protocol`：Client/P1/P2 协议编排；只处理通用控制器数据和 shares。
- `execution`：统一的控制器运行接口 `step(v) -> u`。
- `simulation`：领域无关的 scenario plan、时间循环、runner 和八字段结果契约。
- `scenarios`：plant、reference、controller design、信号适配及单位等领域逻辑。
- `experiments`：显式选择已实现的场景、记录 provenance，并发布/读取通用结果产物。

仿真引擎不得自行计算 `reference - measurement`。scenario adapter 根据 reference 和 plant output
构造 controller input `v`，因此未来场景可以传入完整 state、state error 或 observer output。
更多说明见 [架构文档](docs/architecture.md)。

## 环境

- Windows
- Python 3.11
- 使用 `uv` 管理 Python、项目依赖、项目目录内的 `.venv` 与 `uv.lock`

## 开始使用

在项目根目录同步锁定的依赖：

```powershell
uv sync --locked
```

运行测试：

```powershell
uv run pytest
```

运行静态检查：

```powershell
uv run ruff check .
uv run ruff format --check .
```

运行 Python 程序或模块：

```powershell
uv run python path\to\script.py
uv run python -c "import secure_control; print(secure_control.__version__)"
```

实验配置使用场景选择外壳：

```yaml
scenario:
  name: hvac
```

通用 `simulation.runner.run(scenario)` 不根据 YAML 选择场景；具体 HVAC 装配位于场景层。
实验入口只显式支持 `hvac`；未实现的场景名会明确失败。

## HVAC 场景基线

[`configs/hvac_baseline.yaml`](configs/hvac_baseline.yaml) 冻结了 HVAC 的一阶 RC 冷却模型、60 s
采样、3 小时 horizon、15 → 20 → 25 °C reference、控制量方向、结果通道及 `v = r - T` 的场景
信号适配语义。项目已提供确定性的 HVAC plant、reference、signal adapter、PID 到通用状态空间
矩阵的转换、场景级明文闭环基线，以及复用通用 engine 的 180 步安全双闭环。运行双闭环：

```powershell
uv run python -m secure_control.scenarios.hvac.runner --config configs/hvac_dual_loop.yaml --seed 12
uv run python -m secure_control.scenarios.hvac.runner --config configs/hvac_2r2c_dual_loop.yaml --seed 42
uv run python -m secure_control.scenarios.hvac.runner --config configs/hvac_2r2c_dual_loop_25_20_15.yaml --seed 42
```

`--seed` 仅用于隔离测试复现；省略时使用安全随机材料源。CLI 只输出摘要，不保存 #13 的
正式结果文件。配置、时间索引、范围证书与公平比较见
[HVAC 双闭环集成](docs/simulation_hvac_integration.md)。详细 PID 设计见
[HVAC PID 设计](docs/hvac_pid_design.md)；完整场景约定见
[HVAC 场景契约](docs/hvac_scenario_contract.md)。

2R2C 配置使用确定性 10,179 候选 plaintext exhaustive grid，冻结 gains 为
`Kp=-0.85, Ki=-0.0007, Kd=-0.5`。调参规则、完整指标、二维有限时域范围和论文适配边界见
[2R2C HVAC PID 设计](docs/hvac_2r2c_pid_design.md)。该结果是 adapted application，不能称为
论文原数值实验复刻，也不声明无限时域稳定性。

Issue #53 将正式参考迁移为 25→20→15 °C；当前 PID 先经独立 plaintext 门禁并直接复用，
没有重新执行网格搜索。新配置链、稳定 baseline identity、180 步证书和历史证据边界见
[2R2C HVAC 参考迁移](docs/hvac_reference_migration.md)。旧 15→20→25 配置及其下游报告继续作为
历史证据保留，不自动代表新正式基线。

保存正式八字段实验产物使用独立入口，不改变上面的场景级摘要 CLI：

```powershell
uv run python -m secure_control.experiments.runner --config configs/hvac_dual_loop.yaml --seed 12
uv run python -m secure_control.experiments.runner --config configs/hvac_2r2c_dual_loop.yaml --seed 42
uv run python -m secure_control.experiments.runner --config configs/hvac_2r2c_dual_loop_25_20_15.yaml --seed 42
```

每次运行创建独立的 `results/csv/<run_id>/trajectory.csv`、`metadata.json` 和
`config.json`；固定测试 seed 可重跑相同数值内容，已存在 run 不覆盖。schema、
通道单位、有效配置快照、公开 provenance、失败与读取语义见
[实验产物约定](docs/experiment_schema.md)。普通生成产物默认不提交 Git。

从上述完整成功 run 读取数据生成 HVAC 四类对比图（tracking、applied control、
control error、output error），不重新运行双闭环：

```powershell
uv run python -m secure_control.experiments.figure_runner --run-dir results/csv/<run_id> --control-error-scale log
```

把 `<run_id>` 换成实际已发布目录名。默认单通道 HVAC 使用小时轴并输出四张 PNG
到 `results/figures/<run_id>/<render_id>/`；向量通道必须显式提供可重复的
`--tracking output:reference` 与 `--control-channel index`，也可选择 linear/log 和
PNG/PDF。无同单位 reference 的输出误差可用可重复的 `--output-error-channel index`
独立选择；省略时沿用 tracking 的输出通道。图只修改渲染副本，不反写原始数据；
路径、单位、log 零值与追溯清单见
[已保存结果绘图契约](docs/figure_contract.md)。普通生成图片默认不提交 Git。

运行冻结的 2R2C 定点精度扫描：

```powershell
uv run python -m secure_control.experiments.sweep_runner --definition configs/hvac_2r2c_precision_sweep.yaml
```

扫描固定 plant、PID、reference、horizon、执行器、256-bit 素数与 `lambda=80`，只比较
`ell={32,40,48,56}`（对应 `k=ell+28`）和三个测试材料 seed。每点先验证来源摘要、
Pocklington 证据、局部稳定性报告与有限时域整数范围，再发布原始八字段结果、标准图、跨精度图、
指标和精确推导的协议资源数。完整定义、状态语义和结论边界见
[2R2C 定点精度扫描](docs/precision_sweep.md)。这些结果是 adapted application，不是论文原数值
实验的逐项复刻。

从冻结 sweep 只读生成 01–12 中文阶段汇报图：

```powershell
uv run python -m secure_control.experiments.sweep_figure_runner --sweep-dir results/sweeps/<sweep_id> --display-config configs/hvac_2r2c_report_zh.yaml --output-root results/figures/reports
```

报告不会重跑实验或写回 sweep；中文 profile、字体 glyph 预检、科学计数法、固定图目录、
原子发布与追溯边界见 [2R2C HVAC 中文汇报图](docs/chinese_report_figures.md)。

为冻结代表点生成默认关闭的真实安全执行证据，并从 verified sweep/evidence 只读生成增强报告：

```powershell
uv run python -m secure_control.experiments.evidence_runner --source-sweep-id 20260917T141734484659Z-0b0eb456cc01 --ell 48 --seed 42 --trace-step 60 --allow-combined-share-diagnostic
uv run python -m secure_control.experiments.evidence_report_runner --source-sweep-id 20260917T141734484659Z-0b0eb456cc01 --trace-id <trace_id>
```

该路径严格复验正式八字段，不修改已有 sweep。公开 evidence 与短时 combined-share 诊断物理隔离；
增强报告使用分钟轴、applied-control Fig. 3 adapted、三 seed timing 与 exact 协议资源。完整命令、
文件闭包、安全声明和 Protocol 2 计数为零的含义见
[安全执行证据与增强中文报告](docs/secure_execution_evidence.md)。

## 安全算术基线

`secure_control.crypto` 现已提供与场景无关的定点编码、2-out-of-2 加法秘密共享、标量 Beaver
三元组乘法和论文 Protocol 2 的标量截断。所有模整数使用 canonical residue `[0, q)` 存储，并在
需要时显式恢复中心化有符号表示；数组中的模整数使用 Python 任意精度 `int` 与 `dtype=object`，
避免固定宽度整数溢出。

- 定点数的论文取整、尺度和模表示：[定点数约定](docs/fixed_point_contract.md)
- 共享、公开线性运算与随机性：[秘密共享约定](docs/secret_sharing_contract.md)
- Beaver Protocol 1 与三元组一次性消费：[Beaver 三元组约定](docs/beaver_triple_contract.md)
- Protocol 2 截断、中心化低位与消息流：[截断协议约定](docs/truncation_protocol_contract.md)
- 跨原语尺度、资源和随机性验证：[安全算术组合 Gate](docs/secure_arithmetic_gate.md)

组合 Gate 的随机路径可单独运行：

```powershell
uv run pytest tests/test_secure_arithmetic_gate.py -k randomized -q
```

安全算术当前只实现 scalar-first 的 Beaver 与截断路径。它验证本地协议算术与消息语义，并不等同于
主机隔离、网络安全或完整的生产级安全证明。进程隔离与网络通信仍属于后续工作。

## 通用两方协议核心

`secure_control.protocol` 现已提供领域无关的 `Client`、`P1`、`P2`、显式消息/资源对象与
`SingleProcessCoordinator`。Client 分别分发通用 `ControllerSpec(A, B, C, D, x0)` 的份额；每个
在线 step 对 `C/D/A/B` 的每个标量矩阵项消耗一份独立 Beaver triple；只有 scale ledger 要求
state rescale 时，聚合 state 的每一行才消耗一对截断随机量。output 保持 ledger 声明尺度并只在
Client 边界解码。P1/P2 不保存第二份参数、输入、state 或资源 share。

Protocol 3 以 `ControllerScaleLedger` 明确每类 operand、accumulator、Trunc 和输出尺度。首版
支持固定点 A/B 的逐 state 行 Trunc，以及 metadata 声明的整数 A/B no-Trunc 路径；Client 还
要求公开编码 payload 范围契约，以证明 state 与 output 不发生不可解释的模回绕。单进程路径仅
验证协议消息流与算术语义，不是进程或网络隔离声明。角色可见数据、资源计数、失败清理见
[通用两方协议契约](docs/two_party_protocol_contract.md)。

`SecureStateSpaceRuntime` 将上述协议封装为 `step(v) -> u` 与 `reset()`，上层不接触
Client/P1/P2、share 或一次性资源。输入 shape、更新顺序和输出 shape 与明文 runtime 对齐；
尺度、事务式失败语义、数值容差和当前 backend 限制见
[通用安全状态空间运行时契约](docs/secure_runtime_contract.md)。

仿真产生的大量 CSV、图片、扫描与诊断工件应分别写入 `results/csv/`、`results/figures/`、
`results/sweeps/` 和 `results/diagnostics/`；这些输出默认不会提交到 Git。
