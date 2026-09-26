# 配置文件怎么选

日常只需认清两条入口：**三个文件各启动一个角色的连续实验**，或**一个命令生成四精度 Fig3 图**。二者复用部分论文对象和数值证据，但运行方式、结果目录不同。

| 想做什么 | 运行入口 | 需要看的配置 | 输出 |
| --- | --- | --- | --- |
| 一台或三台电脑分别启动 P1、P2、Client，完成一次连续实验 | `scripts/run_continuous_p1.py`、`run_continuous_p2.py`、`run_continuous_client.py` | 通常只改 `paper_pid_lan.example.yaml`；三机时还要改各机内容相同的 `local-deployment.example.yaml` | Client 配置指定的 `results/lan_continuous/<run-id>/control.png` |
| 一次算完 `ell=32/40/48/56` 并画一张 Fig3 对比图 | `python -m secure_control.experiments.paper_pid_fig3` | `paper_pid_fig3_sweep.yaml`；它引用的论文对象与素数证据是冻结输入 | 新输出目录下的 `fig3.png`、`manifest.json` 和四个 run |

## 三角色连续实验

倒立摆专用入口仍先启动同一 P1/P2，再运行 `scripts/run_cart_pole_client.py`：
默认持续 Tk 动画，`--segment-steps 400` 是每段容量，点击“停止并保存”才确定实际 N；
不修改 `cart_pole_balance.yaml` 的有限 horizon。Client 使用
`lab-client-cart-pole.example.yaml` → `cart_pole_lan.example.yaml` 的单一 profile，
后者引用原 plant/balance 和共享素数证明。`--finite` 保留旧有限窗口，
`--headless-continuous` 仅返回真实 stopped；这两个选项互斥。
新的完整结果保留实际 N、独立对照、双回执和八字段有限块，
详见[倒立摆操作指南](../docs/cart_pole_interactive.md)。

- `lab-p1.example.yaml`、`lab-p2.example.yaml`、`lab-client-continuous.example.yaml`：三个脚本各自默认读取的角色配置；`transport: insecure_tcp` 明确表示网络连接不加密、不验证对端。P1/P2 不配置实验精度。
- `paper_pid_lan.example.yaml`：**Client 的日常参数入口**，包含场景、`ell`、`k`、`runtime_payload_bits`、`lambda`、步数和结果目录。改 `ell` 时不能只改一个数字；当前 51 步配置建议同时保持 `k=ell+8`、`runtime_payload_bits=ell+14`，并让程序完成数值预检。该入口的合法组合均标记为 `user-exploration`；Fig3 的四个冻结精度只由它自己的定义管理。
- `scenario: paper_pid_fig3` 是已有 paper PID 数学场景的标识；在三角色配置里出现这个名字不会启动 Fig3 四点扫描。
- `local-deployment.example.yaml`：三条固定连接的地址和端口；本机的 `127.0.0.1` 不用改。跨电脑时三份文件内容须相同，填实际 LAN IP，并确认端口可访问。它只描述拓扑；连接模式由角色配置决定。
- `shared_prime_256_pocklington.yaml`：Client profile 使用的跨场景公开素数证明，日常不要手动修改。

旧 TLS 和单步 LAN 示例配置已从当前目录移除；安全协议的回归测试仍保留。

## Fig3 四精度批量图

在项目根目录用 PowerShell 或命令提示符运行。先只查看已经发布的四点结果，**不重新计算**：

```text
uv run python -m secure_control.experiments.paper_pid_fig3 --verify-dir results/paper_pid_fig3
```

要重新计算四点并出图，给它一个**不存在或空的**新输出目录：

```text
uv run python -m secure_control.experiments.paper_pid_fig3 --config configs/paper_pid_fig3_sweep.yaml --output-root results/diagnostics/my_fig3_run --seed 70
```

这个命令默认在一个进程里顺序跑四个精度；它不是三个手动启动的 LAN 角色。`--backend localhost` 是另一个自动启动本机三个进程的诊断方式，也不是三台物理电脑。当前三角色 LAN 入口一次只运行一个精度，生成的是单次 `control.png`；现有 Fig3 reader 不接受把四个 LAN run 直接拼成一张图。要让三台电脑的一组角色连续跑四个精度并合成同款 Fig3 图，还需要另行设计批量会话与结果清单。

三角色 Client 的 `paper_pid_lan.example.yaml` 直接引用 `paper_pid_cascade_zoh.yaml`，不读取 Fig3 四点定义；即使选 `ell=32`，此日常入口也标为 `user-exploration`。`paper_pid_fig3_sweep.yaml` 独立引用同一个基线文件和历史名素数证据 `hvac_2r2c_sweep_prime.yaml`，并锁定来源 SHA；已发布的 `results/paper_pid_fig3` 仍需这些原始字节。更多背景见[Fig3 方法与阈值对照](../docs/paper_pid_fig3.md)。

旧 HVAC 示例配置已退出日常入口，测试所需的原始输入位于 `tests/fixtures/legacy_hvac/`。唯一保留在 `configs/` 的旧名 `hvac_2r2c_sweep_prime.yaml` 是 Fig3 已发布清单的哈希兼容来源，不能独立编辑。
