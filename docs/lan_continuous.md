# 独立三角色连续 LAN 实验（Issues #86、#84、#75、#92）

## 持续分段后端（#100）

三个终端仍分别启动原 P1、P2、Client 文件；持续模式由 Client 显式选择：

```powershell
uv run python scripts/run_continuous_p1.py
uv run python scripts/run_continuous_p2.py
uv run python scripts/run_cart_pole_client.py --headless-continuous --segment-steps 400
```

Client 可照旧传入第一个配置路径参数。按 Ctrl+C 提交**正常停止请求**：若本轮已发起，
完成双提交、执行器、物理推进和场景验证，再取得双方段结束回执。没有 in-flight 轮时不再
发起新轮；已建立的会话允许 0 步停止。窗口关闭/硬取消仍属于 cancellation。

`lan-segmented-v1` 每段容量为 1…1000 的整数，默认 400，整次运行没有预设总 N。
P1/P2 同一次启动保持监听；双方确认 continue 后计划关闭旧连接并重新认证，生成新
session、控制器分享、round 和一次性材料。段链核对 run/段索引/全局前缀/上一 session；
公开 setup/layout 必须不变。仅支持零维控制器状态，非零状态明确拒绝，不重构秘密状态。
旧模式的 schema 3、None shutdown、exact-N finish、动态/Trunc 和末端稳定要求不变。
旧服务不能处理新模式；各角色应使用同一版本代码。

### 给 #101 / #103 的后端契约

`experiments.lan_runner.run_client_segmented(config, segment_steps=400, control=RunControl(),
on_step=..., on_segment=..., session=...)` 是同步 worker。`control.request_stop()` 线程安全、
幂等，不关闭连接；`session` 是可选的原 `InteractiveSession` 扰动队列。
重复停止不会再次执行场景拒绝回调；SIGINT 在场景持锁或收尾期间也可返回，
首次停止仍串行设置扰动门禁，不清空在途步所需的请求。
停止接纳后拒绝新扰动，已发起区间仍可锁存一项此前请求，完成后拒绝剩余队列。

- `LanSegmentedRuntime.step(v)` 返回冻结的 `SegmentedStep`（或停止先获门禁时返回 None）；
  raw control 是 tuple。只有上层完成实际推进及验证后才可 `confirm_applied(identity)`，
  同一对象一次确认，未确认时禁止下一轮/续段/正常结束。
- `on_step(ConfirmedStep)` 只在协议与物理均确认后调用；包含只读协议身份/资源和场景快照，
  时间为全局整数步乘 Ts。`on_segment(CompletedSegment)` 只在双方结束回执匹配后调用；
  包含当前段步骤、setup、prime/range/scale 摘要、连接耗时及双方本地计数回执。
  两个可靠记录回调抛错都使 run 失败。运行时仅持有当前段 O(L) 记录，不保存全程列表。
- 正常结果是 `status=stopped, stop_reason=user_requested`，公开 C、next_global_step、
  C*Ts、observed_status、资源累计数和最终段/双方回执。recovering 也可正常停止。
- 故障结果为 failed/uncertain/cancelled，含 failure_phase、已知协议提交计数和物理确认
  前缀、可能未确定的 round/session。uncertain 中计数是已知下界，不推测丢失回执对应的
  远端提交，也不重试旧轮或续段。已知故障即使两个计数相同也不能变成 stopped。

停止若到达已发送 continue 之后，先核对该次过渡，然后建立新容量正数但实际 0 步的
末段，并取得双方 stop 回执；不能把 continue 回执当最终停止。握手/idle/step/shutdown
均保留有界 timeout；计划重连的墙钟开销不会推进仿真时间，不承诺 20 ms 实时控制。
Client 保留唯一真实 plant、adapter、monitor、目标及扰动队列，段界不重置观测稳定计数。
冻结数值来源每次续段重查，配置变化失败退出，不热切换增益或工作域。

该 headless 后端不写长轨迹正式产物或运行 ideal 重放。
默认 `scripts/run_cart_pole_client.py` 的 Tk 持续窗口在同一个 prepared 执行入口上
增加“停止并保存”、可靠分段暂存、停后独立重放及 guarded 完整发布；
用 `--finite` 保留有限窗口。操作和 format v1/v3 reader 见
[倒立摆持续动画](cart_pole_interactive.md)。新 runner 可选 `phase` 回调在实际阶段通知，
没有回调的 headless 调用仍返回原 stopped/失败契约。
stopped 不是 artifact complete。控制律/阶段切换及非零秘密状态迁移由后续设计决定。
本机三进程和 TLS/insecure 两种传输测试不替代 #76 的真实三机或实时验收。

此入口在三个独立进程运行 paper-inspired PID、四水箱或近直立倒立摆的连续安全闭环。三条连接
Client→P1、Client→P2、P2→P1 使用无证书实验 TCP。P1/P2 只读角色配置、公开
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
Paper PID/四水箱的最终 JSON 中 Client 的 `status: complete` 与 P1/P2 的 `status: closed` 表示各自运行结束；
倒立摆只有 Client 完成末端稳定判定、正式 artifact 发布和复验后，整次运行才算成功，
P1/P2 的 `closed` 单独不足以证明这一点。
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
只在 Client 修改所选实验 profile；P1/P2 不需要复制场景或控制器参数。
真正三机网络的可达性与图输出仍需在实际三台电脑上验证。切换水箱时，将 Client
角色配置的 `experiment` 指向 `configs/quadruple_tank_lan.example.yaml`；倒立摆指向
`configs/cart_pole_lan.example.yaml`。不能只改
Paper PID profile 的 `scenario` 字段。

## Client 实验配置

`configs/lab-client-continuous.example.yaml` 的 `experiment` 指向
`configs/paper_pid_lan.example.yaml`，也可指向 `configs/quadruple_tank_lan.example.yaml`
或 `configs/cart_pole_lan.example.yaml`。
P1/P2 的 YAML 没有场景字段；三方仍引用同一
topology。实验 profile 允许修改：

- `sample_count`：Paper PID/四水箱的真实连续步数，采样分别为 `0.1 s`/`0.5 s`；
  倒立摆直接从 `cart_pole_balance.yaml` 读取 `horizon_steps` 和物理采样周期，profile 不重复这些值。
- `numeric.ell`：定点小数位；`numeric.k`：论文 `Q<k,ell>` 中参数/初态的**有符号总 payload 位宽**，并非整数位数；`runtime_payload_bits`：动态输入和 state 的总 payload 位宽。
- `numeric.lambda`：Protocol 2 安全参数；`numeric.prime_source`：唯一公开 q/素数证据文件。不要在 profile 中复制 q。若 q 大于 64 位，角色必须收到并各自验证证书。
- `range.measurement_absolute_bound`：Paper PID 单路测量界；四水箱改用
  `measurement_absolute_bounds_v: [256, 256]`，两路界分别预证明并在线检查。
- `plot.control_channel`：Paper PID 只能选 0，四水箱可选 0/1；`output_root`：正式 run 目录根。
  运行 ID、nonce、结果与私钥内容都不在实验 profile 中。

启动前校验重复/未知 YAML 键、q/证书、`k>ell`、runtime payload 位宽、
`κ=q.bit_length()-lambda-2>ell`、参数编码及有限 horizon state/output 范围。
不会自动降低参数或替换模数。日常 LAN profile 直接引用 paper PID 基线，
合法值均记为 `user-exploration`。独立 Fig3 定义保留四点冻结声明。两者均为 paper-inspired，
不能升格为作者原数值复现。修改合法精度并重新启动三个角色会得到独立的新 run。

### 我要改什么

| 需求 | 唯一编辑点 | 门禁或归属 |
| --- | --- | --- |
| 场景、`ell`、`k`、`runtime_payload_bits`、`lambda`、步数、测量界、绘图通道、输出目录 | `configs/paper_pid_lan.example.yaml` | Client profile；场景目前只能是 `paper_pid_fig3`，`sample_count≥1`、`ell>0`、`k>ell`、runtime bits≥k、`lambda>0`、`κ=q.bit_length()-lambda-2>ell`；不合法在联网前失败。日常 LAN 值均标 `user-exploration`。四种精度须分别运行四次。 |
| q 和公开 Pocklington 证据 | profile 的 `numeric.prime_source` 指向 `configs/shared_prime_256_pocklington.yaml` | 共享公开安全证据，不属于 HVAC plant；更换 q 时须提供匹配证书并通过启动前验证。历史旧名只供冻结读取。 |
| 机器 IP、三条固定端口、角色名 | `configs/local-deployment.example.yaml` | 三台电脑上的内容须相同。真实三机部署与验收属于 #76。 |
| 连接方式 | 三份 `configs/lab-*.example.yaml` 的 `transport: insecure_tcp` | 明确选择无证书明文实验，不认证对端，不得当作安全 LAN 证据。 |

例如将 `k` 设为不大于 `ell`，或将 `lambda` 设得使 `κ≤ell`，会在网络连接前以配置错误退出；
坏证书同样失败。修改合法 `ell` 时，按 `k=ell+8`、`runtime_payload_bits=ell+14`
调整可得到新的探索 run；所有值仍需经过实际范围门禁。

## 结果、图与重绘

正式 `trajectory.csv/config.json/metadata.json` 保持八字段 v1。`control_ideal` 与
`control_secure` 是 actual applied 控制量；Paper PID/四水箱当前恒等 actuator 使 raw=applied；
倒立摆由场景侧将 raw force 裁剪为 ±10 N，单独保存和复验 raw 证据。
Paper PID 的控制单位为 `paper_unit_unspecified`，倒立摆为 N。同批发布的
`control.png` 有三栏：上为 `u(t)`、中为
`û(t)`，两栏共享同一纵轴范围和刻度；下为有符号 `u−û`，共享秒时间轴。
`control_plot.json` 绑定 run ID、CSV/config/图摘要、通道与样本数。reader 会复验附加文件；
图生成失败没有可读为 success 的 run 目录。`reference=unused_zero` 只是 schema 占位，
不是设定值阶跃。

Client 成功 JSON 的 `figure_path` 与同一 `run_dir/control.png` 对应，且只在正式 reader
和图清单验证后返回。`config.json` 记录有效 profile、来源 SHA、场景和精度，
`metadata.json` 记录状态、通道、单位及 provenance；`trajectory.csv` 为逐步原始轨迹。
Paper PID 控制通道为 0，单位 `paper_unit_unspecified`；四水箱控制通道为 0/1，
单位 `V_deviation`。无真实 ideal 支的未来场景
不得伪造对比曲线。网页直播/回放仍见 [#72](https://github.com/GNYKCZ/secure_pid_hvac/issues/72)。

仅从已验证结果单独重绘，不启动协议：

```powershell
uv run secure-control redraw --run-dir results/lan_continuous/<run-id> --output results/lan_continuous/redrawn.png
```

重绘默认读取已验证的 `control_plot.json` 中的选定通道，因此四水箱原图选通道 1
时不会误绘通道 0。倒立摆的 `cart_pole_evidence.json` 还须由
`load_verified_cart_pole_run` 在 canonical reader 之后重放四维轨迹、限幅及末端判定；
普通 `redraw` 只验证通用 v1 图与文件摘要，不代替场景成功判定。

## 四水箱 Fig. 4 对照

Client profile 分别设 `ell=32/40/48/56`、`k=ell+8`、
`runtime_payload_bits=ell+14`，每次重启 P1/P2/Client 并保留四个独立正式 run。
固定定义在 `configs/quadruple_tank_fig4.yaml`，只读汇总命令为：

```powershell
uv run python -m secure_control.experiments.quadruple_tank_fig4 --run-dirs <ell32-run> <ell40-run> <ell48-run> <ell56-run> --output-root results/quadruple_tank_fig4
uv run python -m secure_control.experiments.quadruple_tank_fig4 --verify-dir results/quadruple_tank_fig4
```

仓库中的 `results/quadruple_tank_lan/` 保存四次独立本机三进程 run，
`results/quadruple_tank_fig4/` 保存来源清单和对照图。汇总只读取经 canonical
reader 与单次图清单验证的结果，不运行协议。每次为 51 个更新前样本 `t=0…25 s`；
两路有符号 `u−û` 从 CSV 重算 L2 范数，零值保留，并与 `ε=2^-10` 对照。
51 步的实际资源证据为 1836 份乘法材料、204 份 Trunc 材料及逐步双提交。
这采用 #73 的 ZOH/偏差初态解释和仓库已审计素数；`[256,256] V` 与动态
payload 位宽是经范围证明的项目选择。论文未公开离散矩阵、精确素数、随机种子或
Fig. 4 逐点数据，故图是论文参数衍生的线性数值/协议对照，不是作者原图逐点复刻。
高精度结果在 binary64 分辨率附近时，清单记录 ULP 和零样本数。

## 接入下一个离散状态空间场景

新场景须在自身 `scenarios/<name>/` 中提供 `ControllerSpec` 来源、数值/测量界
证明、独立 ideal/secure 的 `SimulationPlan` 与明文基线核对；在 `experiments/`
中提供严格的 Client profile loader（含来源摘要、素数和绘图通道），并在
`lan_continuous_profile.py` 的 `load_prepared_lan_experiment` 增加一个显式选择项，
返回相同的 `PreparedLanExperiment` 记录。此记录给共用 Client 提供数值契约、
双支计划、结果/来源复核及有效配置。`lan_runner.py` 只消费该记录；
P1/P2、`LanContinuousRuntime`、crypto/protocol 与 schema v1 writer/reader
均不需要场景分支。这个接点仅适用于现有 `ControllerSpec` 离散状态空间契约。

自动拉起三个本地角色的 localhost 后端仍用于固定 seed 的数值/消息诊断；本入口验证
独立命令的明文实验 session。两者复用 `Protocol3Orchestrator`、`_complete_client_round`
与八字段 reader，不复制乘法、Trunc 或场景特化协议。

## 当前文件用途

- `configs/lab-p1.example.yaml`、`lab-p2.example.yaml`、`lab-client-continuous.example.yaml`：三个独立角色入口。
- `configs/local-deployment.example.yaml`：三条连接的地址和端口；三台电脑内容须一致。
- `configs/paper_pid_lan.example.yaml`：Client 日常参数，直接读取 `paper_pid_cascade_zoh.yaml` 和共享素数证明；不依赖 Fig3 四点定义，运行声明为 `user-exploration`。
- `configs/paper_pid_fig3_sweep.yaml`：四点图独占的冻结定义，仍读取历史名 `hvac_2r2c_sweep_prime.yaml`，因为已发布 Fig3 清单绑定文件名和原始 SHA。

旧 LAN/TLS 示例配置和 VS Code 调试清单已移除。历史 HVAC 配置仅留在 `tests/fixtures/legacy_hvac/` 供内部回归；它们不是日常实验入口。正式 `results/paper_pid_fig3/` 证据和四点 reader 保留。三角色与 Fig3 复用同一个 paper PID 场景计算，不复制安全协议。
