# secure_pid_hvac

本项目用于研究论文 *Client-Aided Secure Two-Party Computation of Dynamic Controllers*
中的两方安全动态控制思想。第一个实验场景是 HVAC + PID；未来计划加入 Inverted Pendulum
等场景，并复用同一套控制器规格、安全算术、两方协议、执行层和仿真基础设施。

GitHub 仓库和发行包继续使用 `secure_pid_hvac` / `secure-pid-hvac`，Python 导入包使用更通用的
`secure_control`。HVAC 是第一个场景，不是核心领域；它的模型、参考轨迹、PID 设计、信号适配、
单位和指标应集中在 `secure_control.scenarios.hvac`。

当前已完成架构基础、HVAC 明文基线，以及安全算术原语与组合验证门。尚未实现通用安全控制器
运行时、Client/P1/P2 完整编排、HVAC 安全闭环、multiprocessing 或网络通信。

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

未来配置统一使用场景选择外壳：

```yaml
scenario:
  name: hvac
```

当前阶段仅冻结该配置边界，尚未提供通用 simulation runner。

## HVAC 场景基线

[`configs/hvac_baseline.yaml`](configs/hvac_baseline.yaml) 冻结了 HVAC 的一阶 RC 冷却模型、60 s
采样、3 小时 horizon、15 → 20 → 25 °C reference、控制量方向、结果通道及 `v = r - T` 的场景
信号适配语义。项目已提供确定性的 HVAC plant、reference、signal adapter、PID 到通用状态空间
矩阵的转换，以及场景级明文闭环基线；通用 simulation runner 仍未实现。详细设计见
[HVAC PID 设计](docs/hvac_pid_design.md)；完整场景约定见
[HVAC 场景契约](docs/hvac_scenario_contract.md)。

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
主机隔离、网络安全或完整的生产级安全证明。安全 PID、Client/P1/P2 编排和 HVAC 安全闭环将在后续
Issue 中建立在该 Gate 之上。

仿真产生的大量 CSV 文件与图片应分别写入 `results/csv/` 和 `results/figures/`；这些输出默认
不会提交到 Git。
