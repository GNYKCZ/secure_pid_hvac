# 独立三角色连续 LAN 实验（Issues #86、#84）

此入口在三个独立进程运行 paper-inspired PID 的连续安全闭环。三条连接
Client→P1、Client→P2、P2→P1 可使用实验明文 TCP 或已有双向 TLS 1.3。P1/P2 只读角色配置、公开
数值 setup 与本方 share/资源；plant、PID 场景、明文测量及两份输出重构只在 Client。
本机实验不证明真实三台电脑的网络时延、采样周期或生产安全，也不宣称作者原 plant 的逐点复现。

## 直接运行 Python 文件：无证书实验仿真

在三台电脑分别取得同一版本代码并运行 `uv sync --locked`，在 VS Code 选择项目
`.venv` 的 Python 3.11 解释器。本机试验可直接使用示例的 `127.0.0.1` 地址：

1. 打开 `scripts/run_continuous_p1.py`，点击右上角 **运行 Python 文件**，等待。
2. 打开 `scripts/run_continuous_p2.py`，同样点击运行，等待。
3. 打开 `scripts/run_continuous_client.py`，同样点击运行；成功时 JSON 中的
   `status` 为 `complete`，`figure_path` 是图的完整路径，图保存在 Client 电脑。

每个角色成功载入配置后会打印“配置检查通过”。P1/P2 随后打印“已启动，正在等待
Client”，等待期间终端保持安静是正常的；连接后会打印“协议连接已建立”，
Client 收到三方就绪回执后打印“开始连续计算”，最后打印“运行完成”。
这些提示会显示在终端里，不改变供脚本读取的最终单行 JSON。
最终 JSON 中 Client 的 `status: complete` 与 P1/P2 的 `status: closed` 都表示成功；
`status: failed` 表示失败。若等待超过角色配置的 `startup: 180` 秒，需重启三方。

如果新电脑上的 PowerShell 出现 `Set-ExecutionPolicy` 激活报错，本仓库的
`.vscode/settings.json` 已让**新建的** VS Code 终端默认使用 Windows 命令提示符。
先关闭旧的 PowerShell 终端，再通过菜单 **终端 → 新建终端**开三个终端。
新建终端只是打开另一个独立命令窗口，原终端里正在等待的 P1/P2 会继续运行；
新终端不会自动运行任何角色。点“运行 Python 文件”时
要确认 VS Code 为每个角色保留了独立终端；也可以从仓库根目录在三个终端分别输入：

```text
uv run python scripts/run_continuous_p1.py
uv run python scripts/run_continuous_p2.py
uv run python scripts/run_continuous_client.py
```

三个命令要分别留在各自终端运行，不能在同一个终端依次等待前一个结束。

这三个文件分别固定角色，默认读取 `configs/lab-p1.example.yaml`、
`lab-p2.example.yaml`、`lab-client-continuous.example.yaml`。也可在命令行把另一份
角色配置路径作为脚本的唯一参数。每次启动都用独立终端，重新实验需重启三方。
`transport: insecure_tcp` 是有意选择的**不认证、无加密**连接；代码仍用角色字段
检查消息路由，但该字段不能证明发送者真实身份。此路径不需要 TLS 证书，结果中
`tls_version` 为 `null`，provenance 明确标记实验安全边界。仅在可信、隔离的
实验网络使用，不能把它当作安全三机通信验收。

分到三台电脑时，三台机器的 `configs/local-deployment.example.yaml` 内容必须相同，
将 `p1_client.host`、`p1_peer.host` 和对应 `bind` 改成 P1 的局域网 IP，
将 `p2_client.host` 和 `bind` 改成 P2 的局域网 IP。Client 无须监听；三台电脑
之间应能访问三个固定端口 `34401`、`34402`、`34403`，防火墙需允许这些端口。
只在 Client 修改 `configs/paper_pid_lan.example.yaml` 的实验参数；P1/P2 不需要
复制场景或控制器参数。真正三机网络的可达性与图输出仍需在实际三台电脑上验证。
当前只实现 `paper_pid_fig3` 场景，不能仅通过改一个场景名切换到尚未实现的水箱。

## 原有 TLS 启动方式

先按 [LAN 单步说明](lan_single_step.md)执行 `uv sync --locked`，在 VS Code 选择本仓库
`.venv` 的 Python 3.11 解释器。VS Code 的 Python 与 Python Debugger 扩展需可用。
准备忽略目录中的短期本机测试证书：

```powershell
uv run python scripts/prepare_local_lan_certs.py
```

在 Run and Debug 依次选择 **Continuous P1**、**Continuous P2**、**Continuous Client**，
每次点击 Run 都进入独立 integrated terminal。三项固定使用
`configs/local-p1.example.yaml`、`local-p2.example.yaml`、
`local-client-continuous.example.yaml`；不要将 #68 的 `local-client.example.yaml` 当作连续入口。
等价的三个独立终端命令为：

```powershell
# 终端 1
uv run secure-control p1 --config configs/local-p1.example.yaml
# 终端 2
uv run secure-control p2 --config configs/local-p2.example.yaml
# 终端 3
uv run secure-control client --config configs/local-client-continuous.example.yaml
```

P1/P2 等待一次连接后，在同一 socket/session 中完成 `sample_count` 个连续 round，
然后各自退出并报告 PID、TLS 版本和提交步数。Client 只在每步双提交、最后一次 plant
更新、两方 shutdown 回执、正式 reader 与图发布均成功后报告 run ID/目录、
场景、`ell`、claim 和绝对 `figure_path`。在终端按该路径定位/打开正式图。退出码与
单步入口相同；失败只输出受限类别/异常类型，不打印 frame、share 或私钥。任一回执
不确定时须停止三方并重新启动，新 session 产生全新资源；`reset` 不在原连接上可用。

## Client 实验配置

`configs/lab-client-continuous.example.yaml` 和原有
`configs/local-client-continuous.example.yaml` 的 `experiment` 都指向
`configs/paper_pid_lan.example.yaml`。P1/P2 的 YAML 没有场景字段；三方仍引用同一
topology；实验模式无需证书，TLS 模式各自仅拥有本机证书与私钥路径。实验 profile 允许修改：

- `sample_count`：真实执行的连续步数；当前场景采样时间为 `0.1 s`，从 step 0 开始。
- `numeric.ell`：定点小数位；`numeric.k`：论文 `Q<k,ell>` 中参数/初态的**有符号总 payload 位宽**，并非整数位数；`runtime_payload_bits`：动态输入和 state 的总 payload 位宽。
- `numeric.lambda`：Protocol 2 安全参数；`numeric.prime_source`：唯一公开 q/素数证据文件。不要在 profile 中复制 q。若 q 大于 64 位，角色必须收到并各自验证证书。
- `range.measurement_absolute_bound`：每步真实测量绝对值的先验界；越界会使运行失败。
- `plot.control_channel`：当前 SISO 场景只能选 0；`output_root`：正式 run 目录根。运行 ID、nonce、结果与私钥内容都不在实验 profile 中。

启动前校验重复/未知 YAML 键、q/证书、`k>ell`、runtime payload 位宽、
`κ=q.bit_length()-lambda-2>ell`、参数编码及有限 horizon state/output 范围。
不会自动降低参数或替换模数。默认 `ell=32,k=40,runtime=46,lambda=80` 与 #70
冻结精度点一致；合法自选值记为 `user-exploration`。两者均为 paper-inspired，
不能升格为作者原数值复现。修改合法精度并重新启动三个角色会得到独立的新 run。

### 我要改什么

| 需求 | 唯一编辑点 | 门禁或归属 |
| --- | --- | --- |
| 场景、`ell`、`k`、`runtime_payload_bits`、`lambda`、步数、测量界、绘图通道、输出目录 | `configs/paper_pid_lan.example.yaml` | Client profile；场景目前只能是 `paper_pid_fig3`，`sample_count≥1`、`ell>0`、`k>ell`、runtime bits≥k、`lambda>0`、`κ=q.bit_length()-lambda-2>ell`；不合法在联网前失败。合法非冻结值标 `user-exploration`。四种精度须分别运行四次。 |
| q 和公开 Pocklington 证据 | profile 的 `numeric.prime_source` 指向 `configs/shared_prime_256_pocklington.yaml` | 共享公开安全证据，不属于 HVAC plant；更换 q 时须提供匹配证书并通过启动前验证。历史旧名只供冻结读取。 |
| 机器 IP、三条固定端口、角色名 | `configs/local-deployment.example.yaml` | 实验与 TLS 示例共用拓扑结构；三台电脑上的内容须相同。真实三机部署与验收属于 #76。 |
| 连接方式 | 三份 `configs/lab-*.example.yaml` 的 `transport: insecure_tcp` | 明确选择无证书明文实验，不认证对端，不得当作安全 LAN 证据。 |
| 证书与各自私钥路径 | `configs/local-{p1,p2,client-continuous}.example.yaml` 中对应角色的 `tls` | TLS 路径每方仅持本方私钥；示例证书只用于本机。 |

例如将 `k` 设为不大于 `ell`，或将 `lambda` 设得使 `κ≤ell`，会在网络连接前以配置错误退出；
坏证书同样失败。修改合法 `ell` 时，按 `k=ell+8`、`runtime_payload_bits=ell+14`
调整可得到新的探索 run；所有值仍需经过实际范围门禁。

## 结果、图与重绘

正式 `trajectory.csv/config.json/metadata.json` 保持八字段 v1。`control_ideal` 与
`control_secure` 是 actual applied 控制量；当前恒等 actuator 使 raw=applied，单位
`paper_unit_unspecified`。同批发布的 `control.png` 有三栏：上为 `u(t)`、中为
`û(t)`，两栏共享同一纵轴范围和刻度；下为有符号 `u−û`，共享秒时间轴。
`control_plot.json` 绑定 run ID、CSV/config/图摘要、通道与样本数。reader 会复验附加文件；
图生成失败没有可读为 success 的 run 目录。`reference=unused_zero` 只是 schema 占位，
不是设定值阶跃。

Client 成功 JSON 的 `figure_path` 与同一 `run_dir/control.png` 对应，且只在正式 reader
和图清单验证后返回。`config.json` 记录有效 profile、来源 SHA、场景和精度，
`metadata.json` 记录状态、通道、单位及 provenance；`trajectory.csv` 为逐步原始轨迹。
当前 SISO 控制通道为 0，单位 `paper_unit_unspecified`。无真实 ideal 支的未来场景
不得伪造对比曲线。网页直播/回放仍见 [#72](https://github.com/GNYKCZ/secure_pid_hvac/issues/72)。

仅从已验证结果单独重绘，不启动协议：

```powershell
uv run secure-control redraw --run-dir results/lan_continuous/<run-id> --output results/lan_continuous/redrawn.png
```

自动拉起三个本地角色的 localhost 后端仍用于固定 seed 的数值/消息诊断；本入口验证
独立命令的明文实验或 mTLS 连续 session。两者复用 `Protocol3Orchestrator`、`_complete_client_round`
与八字段 reader，不复制乘法、Trunc 或场景特化协议。#68 旧单步命令与 wire 语义保留。

## 文件用途与迁移审计（#84）

按 Git 跟踪路径、CLI/import、测试、文档与正式 manifest 审计。以下历史入口和证据文件均保留；
没有证据证明它们可安全删除。仅删除规范内容重复的 `lab-deployment.example.yaml`
和已有实际文件、不再需要占位的 `configs/.gitkeep`。命名规则：`shared_*` 是跨场景公开安全证据，
`paper_pid_*`/`hvac_*` 是场景参数或历史定义，`local-deployment*`
是共用 topology，`local-*` 与 `lab-*` 是角色配置；日常入口见[配置索引](../configs/README.md)。

| `configs/` 下的文件 | owner／身份 | 引用、哈希与处置 |
| --- | --- | --- |
| `paper_pid_lan.example.yaml`, `lab-client-continuous.example.yaml`, `lab-p1.example.yaml`, `lab-p2.example.yaml`, `local-deployment.example.yaml` | Client profile、三角色、共用拓扑；直运行入口 | 三个 `scripts/run_continuous_*.py` → `lan_config.py`/`lan_profile.py`；`test_lan_continuous.py`。原 `lab-deployment.example.yaml` 与 `local-deployment.example.yaml` 的规范拓扑完全相同，故合并为后者。 |
| `local-client-continuous.example.yaml`, `local-p1.example.yaml`, `local-p2.example.yaml` | 原有认证连接入口 | `.vscode/launch.json` → `lan_config.py`/`lan_profile.py`；保留。 |
| `shared_prime_256_pocklington.yaml`, `hvac_2r2c_sweep_prime.yaml` | 公开 q/证据；前者当前日常维护名，后者历史兼容路径 | 字节须一致；前者由 Client profile 使用，后者被 `paper_pid_fig3_sweep.yaml` 的 raw SHA、HVAC 定义的规范化 SHA 绑定。测试锁定证书及双 SHA；旧文件不得独立编辑。 |
| `paper_pid_fig3_sweep.yaml`, `paper_pid_cascade_zoh.yaml` | paper PID 冻结定义与基线 | `paper_pid_fig3.py:load_definition`、正式 `results/paper_pid_fig3/manifest.json`；路径/raw SHA 不可改。 |
| `hvac_2r2c_precision_sweep_definition.yaml`, `hvac_2r2c_precision_sweep.yaml`, `hvac_2r2c_infinite_safety.yaml`, `hvac_2r2c_infinite_safety_25_20_15_fast_response.yaml` | HVAC 历史扫描、安全定义 | `sweep_runner.py`、`infinite_safety_runner.py` 与对应测试；prime 路径与 LF 摘要绑定，保留。 |
| `hvac_baseline.yaml`, `hvac_dual_loop.yaml`, `hvac_pid_baseline.yaml`, `hvac_2r2c_plant.yaml`, `hvac_2r2c_dual_loop.yaml`, `hvac_2r2c_pid_baseline.yaml` | HVAC 基础／旧参考历史场景 | `README.md` 历史命令、场景测试和报告链；从本页日常入口排除，保留复现。 |
| `hvac_2r2c_dual_loop_25_20_15.yaml`, `hvac_2r2c_pid_baseline_25_20_15.yaml`, `hvac_2r2c_scenario_25_20_15.yaml`, `hvac_2r2c_dual_loop_25_20_15_fast_response.yaml`, `hvac_2r2c_pid_baseline_25_20_15_fast_response.yaml` | HVAC 新参考／快速响应来源 | `docs/hvac_reference_migration.md`、`docs/hvac_pid_redesign.md` 和安全/扫描链；保留。 |
| `hvac_2r2c_evidence_report_profile_zh.yaml`, `hvac_2r2c_evidence_report_zh.yaml`, `hvac_2r2c_report_zh.yaml` | 历史／正式报告配置 | `evidence_report_runner.py`、`reporting.py` 和对应测试；保留。 |
| `lan-client.yaml`, `lan-p1.yaml`, `lan-p2.yaml`, `lan-deployment.yaml`, `local-client.example.yaml` | #68 单步 LAN／部署模板 | `lan_config.py`、`test_lan_single_step.py`、`docs/lan_single_step.md`；不误标为连续，保留。 |

`experiments/` 属实验装配：`lan_runner.py`/`lan_profile.py` 是当前连续入口，
`artifacts.py`/`plotting.py`/`provenance.py` 是共享正式结果、图和来源；
`paper_pid_fig3.py`/`paper_pid_runner.py` 是冻结对照；`runner.py`/`figure_runner.py`
是通用保存和绘图。`localhost_runner.py`/`multiprocessing_runner.py` 是自动拉起后端的
固定 seed 诊断，与独立 mTLS 证据不同。历史扫描、报告和回放入口分别为
`_sweep_worker.py`, `sweep.py`, `sweep_runner.py`, `sweep_artifacts.py`,
`sweep_figure_runner.py`, `sweep_metrics.py`, `sweep_plotting.py`,
`infinite_safety_runner.py`, `exact_grid.py`, `exact_grid_artifacts.py`,
`exact_grid_runner.py`, `evidence_runner.py`, `evidence_artifacts.py`,
`evidence_reporting.py`, `evidence_report_runner.py`, `reporting.py`,
`telemetry_replay.py` 及 `__init__.py`；被同名测试、`docs/precision_sweep.md`、
`docs/final_hvac_evidence_chain.md` 等调用，保留历史 reader 和诊断。

`simulation/{contracts,engine,results,runner,telemetry}.py` 与 `__init__.py` 属通用时间循环、
八字段结果与遥测；`scenarios/paper_pid/{baseline,pid,plant,secure_experiment}.py`
及 `__init__.py` 属 paper PID；`scenarios/hvac/{adapter,baseline,contract,infinite_safety,`
`integration,migration,pid,plant,reference,runner,stability,stability_runner,tuning}.py`
及两个 `__init__.py` 属 HVAC。它们分别被实验装配、场景测试和历史文档引用，
保留场景 ownership，不将 PID/HVAC 下沉到核心。

`execution/lan_{config,runtime,transport}.py` 属独立三角色连接与运行；
`localhost_{codec,runtime,transport}.py`、`_localhost_{peer,workers}.py` 属 loopback 诊断；
`multiprocessing_runtime.py`、`_multiprocessing_workers.py` 属本机多进程诊断；
`{contracts,evidence,runtime,secure_runtime,_inputs}.py` 和 `__init__.py` 属通用执行契约。
`test_lan_single_step.py`、`test_lan_continuous.py`、`test_localhost_transport.py`、
`test_multiprocessing_runtime.py` 为其不同路径提供证据，均保留。

`results/paper_pid_fig3/manifest.json`、`fig3.png` 与四个 run 各自的
`config.json`、`metadata.json`、`trajectory.csv` 是 Git 跟踪的 #70 正式证据，
由 `render_saved_sweep` 和 reader/测试复验；`results/.gitattributes` 固定逐文件换行。
`results/{csv,figures}/.gitkeep` 只保留目录。ignored 的 `results/csv/`、`figures/`、
`sweeps/`、`safety/`、`diagnostics/`、`exact_grid/` 内有本机产物，其中
`docs/final_hvac_evidence_chain.md` 引用的路径与哈希须留存。其余历史测试/探索产物
来源不全，本轮未删除，也未算作已复验。新增精确 ignore `results/lan_continuous/`。
审计时 `git ls-files --others --ignored --exclude-standard results` 列出 3,972 个本机文件：
`csv` 2,897、`figures` 349、`sweeps` 661、`safety` 9、`diagnostics` 50、
`exact_grid` 6。它们均未作为删除目标；逐个来源/哈希尚未建立可核查证据。

`tests/` 未发现可证明纯重复或入口已退出的文件：`test_lan_continuous.py`、
`test_lan_single_step.py`、`test_paper_pid_fig3.py`、`test_paper_pid_baseline.py`、
`test_paper_pid_secure.py`、`test_paper_pid.py` 覆盖当前、冻结、单步；
`test_localhost_transport.py`、`test_multiprocessing_runtime.py`、`test_secure_runtime.py`、
`test_secure_evidence.py`、`test_secure_arithmetic_gate.py`、`test_secret_sharing.py`、
`test_beaver.py`、`test_truncation.py`、`test_two_party_protocol.py`、
`test_fixed_point.py`、`test_prime_contract.py` 守协议与数值边界。
`test_experiment_artifacts.py`、`test_experiment_runner.py`、`test_saved_result_plotting.py`、
`test_figure_runner.py`、`test_sweep_plotting.py`、`test_sweep_metrics.py`、
`test_precision_sweep.py`、`test_infinite_safety_runner.py`、`test_evidence_artifacts.py`、
`test_evidence_runner.py`、`test_evidence_reporting.py`、`test_exact_grid.py`、
`test_report_plotting.py` 守 reader/历史来源。`test_architecture.py`、
`test_contracts.py`、`test_hvac_baseline_migration.py`、`test_hvac_dual_loop.py`、
`test_hvac_infinite_safety.py`、`test_hvac_pid_baseline.py`、
`test_hvac_scenario_components.py`、`test_hvac_scenario_contract.py`、
`test_hvac_stability.py`、`test_invariance.py`、`test_plaintext_runtime.py`、
`test_simulation_engine.py`、`test_smoke.py`、`test_stability.py`、`test_telemetry.py`
守场景/仿真契约。清理决策：全部保留，删除/合并目标为空；没有通过删测试获得绿灯。
