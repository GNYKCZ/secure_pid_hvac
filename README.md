# secure_pid_hvac

## 本机连续实验：直接运行三个 Python 文件

在仓库根目录运行 `uv sync --locked`，在 VS Code 选择项目的 Python 3.11
`.venv` 解释器。依次打开 `scripts/run_continuous_p1.py`、
`scripts/run_continuous_p2.py`、`scripts/run_continuous_client.py`，分别点击
**运行 Python 文件**，让每个程序占用自己的终端。此实验配置使用明文 TCP，
**不需要生成或复制 TLS 证书，也不验证网络对端身份**；仅用于可信、隔离的实验网络。
终端会显示“已启动/等待”“连接已建立”“三方已就绪”和“运行完成”；
P1/P2 在等待 Client 时不持续输出。新终端默认使用命令提示符，避开 PowerShell 的
`Set-ExecutionPolicy` 激活报错；改动 VS Code 设置后须关闭旧终端并新建终端。
Client 完成后输出 run ID、结果目录与 `figure_path`（正式三栏 `control.png`）。
失败时停止三方，再从 P1 重新开始。
场景、精度、步数和输出目录只改 `configs/paper_pid_lan.example.yaml`；
三机 IP、配置归属及验证结果重绘见
[连续 LAN 实验指南](docs/lan_continuous.md)。
配置文件的日常用途和 Fig3 四精度批量入口见[配置索引](configs/README.md)。
当前只支持 `paper_pid_fig3`；网页 Dashboard 属 [#72](https://github.com/GNYKCZ/secure_pid_hvac/issues/72)，
不属于这三项 Run。

本项目用于研究论文 *Client-Aided Secure Two-Party Computation of Dynamic Controllers*
中的两方安全动态控制思想。第一个实验场景是 HVAC + PID；未来计划加入 Inverted Pendulum
等场景，并复用同一套控制器规格、安全算术、两方协议、执行层和仿真基础设施。

GitHub 仓库和发行包继续使用 `secure_pid_hvac` / `secure-pid-hvac`，Python 导入包使用更通用的
`secure_control`。HVAC 是第一个场景，不是核心领域；它的模型、参考轨迹、PID 设计、信号适配、
单位和指标应集中在 `secure_control.scenarios.hvac`。

当前已完成架构基础、一阶与 2R2C HVAC 明文基线、安全算术原语与组合验证门、通用
Client/P1/P2 单进程协议核心、与明文接口兼容的通用安全状态空间运行时，以及领域无关 simulation engine 和
180 步 HVAC 明文/安全双闭环。现已提供显式选择的本机 multiprocessing 后端与仅绑定 loopback
的 localhost TCP 后端；默认安全运行时不变。旧单步 LAN 示例配置已退出日常入口。
独立三终端连续 paper-inspired PID、本机 Client profile 与同次正式三栏控制图见
[连续 LAN 实验](docs/lan_continuous.md)。
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

论文定义、当前通用机制、HVAC 场景适配和尚未实现的 PID/four-tank 原例之间的可声明边界，见
[论文复现范围与实现对照](docs/paper_reproduction_matrix.md)。

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

当前日常实验只需选择三角色连续运行或 Fig3 四点图，入口与配置见上方快速开始。旧 HVAC 命令不再作为用户入口展示，示例输入移入测试夹具；底层实现和相应回归仍供内部验证。

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

需要验证本机角色进程隔离时，可显式使用 `MultiprocessingSecureStateSpaceRuntime`。它以
Windows 兼容的 `spawn` 建立独立 Client/P1/P2 PID，保持同一 runtime 与仿真接口，并提供有界
超时、fail-closed 清理、reset 换组和上下文管理器；默认后端不变。运行与安全边界见
[多进程安全执行](docs/multiprocessing_execution.md)。

需要验证本机 TCP wire schema、framing 与故障清理时，可显式使用
`LocalhostSecureStateSpaceRuntime`。它保持同一 runtime/simulation 接口，并与 multiprocessing
后端复用唯一 Protocol 3 orchestrator；Client 驱动在线轮次，父进程仅交换公开输入与提交后的
结果。不提供 TLS、认证或生产安全声明。运行和对照命令见
[localhost 通信传输](docs/localhost_transport.md)。

仿真产生的大量 CSV、图片、扫描与诊断工件应分别写入 `results/csv/`、`results/figures/`、
`results/sweeps/` 和 `results/diagnostics/`；这些输出默认不会提交到 Git。
