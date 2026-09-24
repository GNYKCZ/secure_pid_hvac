# 配置文件怎么选

日常只需认清两条入口：**三个文件各启动一个角色的连续实验**，或**一个命令生成四精度 Fig3 图**。二者复用部分论文对象和数值证据，但运行方式、结果目录不同。

| 想做什么 | 运行入口 | 需要看的配置 | 输出 |
| --- | --- | --- | --- |
| 一台或三台电脑分别启动 P1、P2、Client，完成一次连续实验 | `scripts/run_continuous_p1.py`、`run_continuous_p2.py`、`run_continuous_client.py` | 通常只改 `paper_pid_lan.example.yaml`；三机时还要改各机内容相同的 `local-deployment.example.yaml` | Client 配置指定的 `results/lan_continuous/<run-id>/control.png` |
| 一次算完 `ell=32/40/48/56` 并画一张 Fig3 对比图 | `python -m secure_control.experiments.paper_pid_fig3` | `paper_pid_fig3_sweep.yaml`；它引用的论文对象与素数证据是冻结输入 | 新输出目录下的 `fig3.png`、`manifest.json` 和四个 run |

## 三角色连续实验

- `lab-p1.example.yaml`、`lab-p2.example.yaml`、`lab-client-continuous.example.yaml`：三个脚本各自默认读取的角色配置；`transport: insecure_tcp` 明确表示网络连接不加密、不验证对端。P1/P2 不配置实验精度。
- `paper_pid_lan.example.yaml`：**Client 的日常参数入口**，包含场景、`ell`、`k`、`runtime_payload_bits`、`lambda`、步数和结果目录。改 `ell` 时不能只改一个数字；当前 51 步配置建议同时保持 `k=ell+8`、`runtime_payload_bits=ell+14`，并让程序完成数值预检。`ell=32/40/48/56` 的冻结组合分别对应 `k=40/48/56/64`、运行位宽 `46/54/62/70`。其他合法组合会标记为 `user-exploration`。
- `local-deployment.example.yaml`：三条固定连接的地址和端口；本机的 `127.0.0.1` 不用改。跨电脑时三份文件内容须相同，填实际 LAN IP，并确认端口可访问。它只描述拓扑；连接模式由角色配置决定。
- `shared_prime_256_pocklington.yaml`：Client profile 使用的跨场景公开素数证明，日常不要手动修改。

原有 `local-{p1,p2,client-continuous}.example.yaml` 是需证书的连续 TLS 入口；`local-client.example.yaml` 和 `lan-{p1,p2,client,deployment}.yaml` 属于较早的单步 LAN 入口。它们仍有文档与测试引用，不能当成未使用文件删除。

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

`paper_pid_fig3_sweep.yaml` 引用 `paper_pid_cascade_zoh.yaml` 和 `hvac_2r2c_sweep_prime.yaml`，并锁定来源 SHA；这些文件与已发布的 `results/paper_pid_fig3` 证据绑定，不要为了改日常 LAN 参数而编辑或删除。更多背景见[Fig3 方法与阈值对照](../docs/paper_pid_fig3.md)。

其余 `hvac_*` 配置支撑已有 HVAC 基线、扫描、报告和历史结果；当前三角色脚本不直接读取它们。它们被测试、文档或已发布来源引用，保留以便复验。
