# 下垂起点两测量完整路线（Issue #103）

[设计评论](https://github.com/GNYKCZ/secure_pid_hvac/issues/103#issuecomment-5864293877)与[用户批准的安全边界](https://github.com/GNYKCZ/secure_pid_hvac/issues/103#issuecomment-5865358983)是本路线依据。原 #102 静态起摆入口、近直立动态入口及其 v1/v2 结果保持各自语义。

从仓库根目录运行明文完整路线，无需 P1/P2：

```powershell
uv run python scripts/run_cart_pole_client.py --full-route plaintext --full-output results/diagnostics/plain-full-v3
```

安全路线先在另两个终端运行 `uv run python scripts/run_continuous_p1.py` 和 `uv run python scripts/run_continuous_p2.py`，再运行：

```powershell
uv run python scripts/run_cart_pole_client.py --full-route secure --full-output results/diagnostics/secure-full-v3 --segment-steps 100
```

窗口入口将 `--full-route` 换为 `--full-gui-route`。`--full-output` 必须是尚不存在的目录；已验证的 `run.json`、`physical.json` 和 `steps.jsonl` 才会发布。输出含终止原因、`goal_met` 和真实完成步数；未达目标的运行返回非零退出码。`--swing-config`、`--observer-config`、`--prime-config` 可指定合法参数源。默认安全路由复用 Client LAN 角色配置和已认证 256 位素数；`insecure_tcp` 只适合可信隔离网络，不提供身份认证或加密。

两条路线各自从声明的下垂初态独立推进 canonical plant。控制只读取 `p` 与连续 `theta` 两测量：k=0 速度种子为零，k=1 一阶后差，其后用因果三点后差。捕获时显式建立新的四维动态 observer；重入会结束旧 epoch 并建立新 epoch。仿真真值仅进入诊断。P1/P2 的固定门计算起摆力，Client 公开判定阶段和安全事件；阶段时间与切换次数因此对双方可见。单个 party 只收到测量、系数和 observer 状态自己的份额。公开 kick 也走双方输出份额路径。

安全起摆使用固定 38 个 Beaver 乘法/Protocol 2 截断门，`ell=80`、`lambda=80`；全声明输入盒的整数/有理界在连接前验证。进入动态捕获后使用原有四维秘密 observer、`ell=32`，逻辑段续跑保持同一秘密状态；跨阶段切换必须等双方结束回执。每个物理区间记录来源、raw/applied/外扰、epoch、轮次、资源身份和物理确认。v3 reader 重放因果观测、阶段、独立理想控制和 canonical plant，并核对双方关闭前缀、资源唯一性、数值精度与配置派生门拓扑。结果摘要用于完整性检查，不提供恶意参与方安全认证。

数值证书覆盖允许输入盒内的算术误差，不声称整个盒子都物理可行；边界状态仍可能在任何允许力下越轨。当前验收是本机三进程仿真，不代表真三机、真实设备、20 ms 墙钟实时、恶意方安全或全局稳定性。
