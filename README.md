# secure_pid_hvac

本项目用于复现论文 *Client-Aided Secure Two-Party Computation of Dynamic Controllers*
中的两方安全动态控制思想，并将控制对象替换为简化的 HVAC 温度控制系统。项目计划同时
提供明文 PID 控制分支和基于定点数、2-out-of-2 秘密共享及安全乘法/截断协议的安全控制分支，
最后比较两条分支的温度与控制输入。

当前项目仍处于工程初始化阶段，仅包含目录骨架和模块占位，尚未实现完整 PID 控制器、
Beaver Triple、截断协议或网络通信。

## 环境

- Windows
- Python 3.11
- 使用 `uv` 管理 Python、项目依赖、项目目录内的 `.venv` 与 `uv.lock`

## 开始使用

在项目根目录同步锁定的依赖：

```powershell
uv sync
```

运行测试：

```powershell
uv run pytest
```

运行 Python 程序或模块：

```powershell
uv run python path\to\script.py
uv run python -m secure_pid.simulation.runner
```

仿真产生的大量 CSV 文件与图片应分别写入 `results/csv/` 和 `results/figures/`；这些输出默认
不会提交到 Git。
