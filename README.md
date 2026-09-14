# secure_pid_hvac

本项目用于研究论文 *Client-Aided Secure Two-Party Computation of Dynamic Controllers*
中的两方安全动态控制思想。第一个实验场景是 HVAC + PID；未来计划加入 Inverted Pendulum
等场景，并复用同一套控制器规格、安全算术、两方协议、执行层和仿真基础设施。

GitHub 仓库和发行包继续使用 `secure_pid_hvac` / `secure-pid-hvac`，Python 导入包使用更通用的
`secure_control`。HVAC 是第一个场景，不是核心领域；它的模型、参考轨迹、PID 设计、信号适配、
单位和指标应集中在 `secure_control.scenarios.hvac`。

当前项目仍处于架构基础阶段，只定义通用数据契约和模块边界。尚未实现 HVAC dynamics、PID
递推、定点运算、秘密分享、Beaver Triple、截断协议、两方协议、进程或网络通信。

## 架构边界

- `core`：通用离散状态空间控制器规格 `A/B/C/D/x0`。
- `crypto`：领域无关的定点数、模运算和安全算术；不得依赖场景。
- `protocol`：Client/P1/P2 协议编排；只处理通用控制器数据和 shares。
- `execution`：统一的控制器运行接口 `step(v) -> u`。
- `simulation`：领域无关的 plant、scenario adapter 和结果契约。
- `scenarios`：plant、reference、controller design、信号适配及单位等领域逻辑。

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

运行 Python 程序或模块：

```powershell
uv run python path\to\script.py
uv run python -c "import secure_control; print(secure_control.__version__)"
```

未来配置统一使用场景选择外壳：

```yaml
scenario:
  name: hvac
```

当前阶段仅冻结该配置边界，尚未提供可执行的 HVAC runner。

## HVAC 场景基线

[`configs/hvac_baseline.yaml`](configs/hvac_baseline.yaml) 冻结了 HVAC 的一阶 RC 冷却模型、60 s
采样、3 小时 horizon、15 → 20 → 25 °C reference、控制量方向、结果通道及 `v = r - T` 的场景
信号适配语义。项目已提供确定性的 HVAC plant、reference 和 signal adapter，但尚未实现 PID 或
simulation runner；完整约定见 [HVAC 场景契约](docs/hvac_scenario_contract.md)。

仿真产生的大量 CSV 文件与图片应分别写入 `results/csv/` 和 `results/figures/`；这些输出默认
不会提交到 Git。
