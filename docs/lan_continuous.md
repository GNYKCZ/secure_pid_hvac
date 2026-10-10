# 独立三角色连续 LAN 实验（Issues #86、#84、#75、#92）

## 批量通信（#116）

三个角色默认通过 `control-batch-v1` 能力握手，同一运行必须使用同一版本程序；
任一角色没有该能力时在 setup 前失败，不自动退回逐门协议。动态控制的一步只向每方
发送一次完整 stage 命令，双方各返回一次 stage 回执；在 30 个乘法、4 个
state 截断的动态基准中，P1/P2 发送 7 个 peer 帧。起摆的 38 个乘法保持原资源顺序和逐门截断，按公开
依赖拓扑分成 16 层，同层交换并在下一层前完成双方屏障，共 80 个 peer 帧。
原有输出重构、双提交、失败轮次烧毁、控制/实验结果 reader 不变。

在可信本机可用下列命令测量三进程回环；`legacy` 仅是**显式诊断模式**，需
Client、P1、P2 同时选择，普通入口默认不启用。报告记录整个会话的各方向应用帧
与字节（含四字节长度头）、Client 逐步耗时、p50/p95/p99、抖动和超过 20 ms
的步数。`--delay-ms` 在每个应用帧发送前加入单向延迟，不模拟 TLS、真实网络
或物理对象，不能把回环结果当作三机采样保证。输出目标须是不存在的新文件。

```powershell
uv run python -m secure_control.experiments.lan_runner benchmark --case dynamic --mode batch --steps 30 --delay-ms 1 --output results/diagnostics/dynamic-batch.json
uv run python -m secure_control.experiments.lan_runner benchmark --case scalar --mode batch --steps 20 --delay-ms 1 --output results/diagnostics/scalar-batch.json
```

比较旧算法通信时将 `--mode batch` 改为 `--mode legacy` 并换一个输出文件名。
诊断报告不保存任何秘密帧、份额、随机数或秘密状态；其 `code_sha`、`dirty`、
配置引用和环境字段需要与具体结论一起阅读。真实三台机器上的时延、超时与
可达性须在实际部署后另行测量。

### 材料分发与持续观察（#121 阶段 P0+A3）

动态 `online` 和 v2 `segment_begin` 先发送两方请求，再分别完整核验 ACK；
P1→P2 双提交和两个 peer 完成屏障保持不变。角色安装 setup 后持有 session
专属 sharing/Mult/Trunc owner，新 setup 重新验证素数证据；每轮仍新建 triple、mask
及 lifecycle，并核验身份、角色、计划、数量和 canonical residue。

`--case continuous --mode batch` 复用 GUI/headless 的唯一持续动态循环，以及现有同步
journal/checkpoint writer。它在指定步数后请求正常停止，临时日志随观察结束清理，
不发布图。段容量只是诊断工作负载，不能据此替代跨 1000 步的长时资格测试。

```powershell
uv run secure-control benchmark --case continuous --mode batch --steps 40 --segment-steps 8 --delay-ms 0 --output results/diagnostics/continuous-observation.json
```

报告保留首步、失败尝试和所有阶段事件：初次连接/预检、输入、网络计算、仿真推进、
逐步可靠写入、段结束/封段与下一段连接。Client 分别记录材料准备、分发、重构和两方
commit；角色记录本地算术、材料恢复、peer 交换、编码/解码、公开 plan 摘要的本机时长。
写入记录包含 source recheck、checkpoint 和 fsync 成本/次数；正常动态步仍有两次 fsync。
统计不剔除首步。失败报告只包含错误类型和公开阶段，CLI 保存报告后返回失败状态。

各项不是可相加的独立 CPU 时间：send/receive 含等待，peer_exchange 含编码与传输，
checkpoint 含自己的 fsync。角色 commit 间隔的 receive 还含等待 Client 下一步的时间；
不使用跨进程绝对时间相减。跨段成本在 events 单列，不能从普通步分布推导完整周期达标。
`source_sha256` 区分同一 HEAD 上的观察/优化补丁，比较时同时核对配置和传输条件。

上述 `continuous` 是显式同步、非实时基准，便于对照；其报告不能代表 20 ms 资格通过。
TCP_NODELAY 试验未显示稳定收益，保持原默认。矩阵 Beaver/预送协议/PRF/PCF 仍未实施。

### 获批周期、预准备和按段保存（#121 A1/A2/A4）

动态持续 GUI/headless 默认从 canonical 场景 `period`（当前 0.02 s）建立一次 t0。
第 k 步始终使用 t0+kT 和 t0+(k+1)T，不跳步、不重设迟到轮的预算。初次 setup、
配置可靠保存、16 轮首池填充及一次初始化垃圾收集在 t0 前完成。
该次收集的耗时/数量由 `startup_gc` 单独报告，之后重新检查取消/停止，才建立 t0。
运行中保留自动 GC 及原阈值，不保证长期回收无停顿；
运行中的 refill、输入、编码/网络、双提交、
设备回执、记录入队和满段维护都受当前 deadline 约束。正常停止确认/drain 单独计时。
`Client.precompute_online_resources` 只创建输入无关的一次性本机能力，
`bind_online_input` 在验证本步新测量后分享输入并签发输出；旧 `prepare_online` 保留。
唯一材料生产者不持 Client 输出签发表、socket 或设备，不替换已有 Mult/Trunc 原语。
库存上限 16、低水位 4；缺货直接失败，无现场补货或新 deadline。每槽预留 512 KiB，
含编码副本的总预留不超过 8 MiB。材料预算仅在启动时编码一次公开最大值模板：
所有 residue（包括输入份额）用 q-1，计划/session/shape/尺度使用本 session 的公开值，
round 与资源 ID 使用工厂固定长度的 ASCII 格式。每方 input/plan 各一个 step，
每资源 metadata 在 plan/material 各一个 step；当轮仅按 step 十进制位宽增加预算。
模板不生成随机材料或签发能力，不提前分享测量，也不发送。补货保留新鲜原语和原 owner。
`material_encoded_bound_high_water` 是两方 payload 的保守上界高水位，
与实际 application bytes、512 KiB 槽预留和 OS RSS 分别报告。
实际在线两方完整 canonical 信封各编码一次、均通过完整帧长度检查后才首次发送；
原 framing 再检查实际长度，两方先发送后收 ACK，不复用跨轮 bytes。

`step(v, *, deadline_ns=None)` 及段过渡的可选 deadline_ns **属于本机
`time.perf_counter_ns()` 时钟域**，不得传入另一机器或 `monotonic_ns()` 的绝对值。
本机 Python 3.11/Windows 的 `monotonic` 可为 15.625 ms 分辨率的 GetTickCount64，
新周期使用高精度且单调的 QPC；旧 timeout/普通 float deadline 保留原 monotonic 语义。
新内部 deadline 标记在两个 canonical transport 剩余时间入口识别，网络保护 timeout
与周期上限在同一高精度时钟内取更早者，绝对钟不进入 wire。CPU/设备 send_control 前
再次检查。迟到且尚未施力时拒绝发送；已发出/完成的设备命令不伪造回滚。提交不确定
保持 UNCERTAIN 并关闭，禁止重连重试。高精度计时不保证 OS 唤醒、网络或硬实时。

动态结果由唯一 writer 按原逻辑段批量保存（默认 400 步，名义约 8 s），仍采用原 v2
journal/hash/checkpoint/封段/完整 reader。控制线程逐步冻结 public bytes，只交接小封段
header 和 immutable 协议身份；整段组装和序列化在 writer。活跃段、最多两个未可靠发布
的封段（含在途段）、metadata 和编码副本共用 8 MiB 预算，出队不提前释放预算。
已有 1…1000 段容量仍有效，但过大记录或后台积压耗尽字节预算时失败，不丢正式记录。
每批 journal 与依赖的 spool/config 先 fsync，再原子发布 checkpoint；不再每步执行两次
fsync/checkpoint。durable_step_count 只表示已发布可靠前缀，可落后于协议/物理确认。
正常停止保存末段并 drain/join 后，原 replay、完整 reader、图和发布门禁全部仍须通过。
控制/记录模块冷启动延后加载 Matplotlib 和报告画布，实际绘图/报告调用时再加载；
公开报告导出仍可用。这减少启动常驻依赖，不保证消除运行中的 GC 或周期超期。
故障先停止 writer，再由唯一 owner 冻结 failure checkpoint；磁盘持续故障保留旧 checkpoint。
崩溃可损失 RAM 尾部，8 s 不是积压情况下的最大损失保证，也不能推断缺失尾部未施力或
据此恢复安全会话。这里比较应用写入次数/字节和 fsync，不宣称 SSD NAND 寿命比例。

公开 CycleTiming v1 记录本机绝对端点、阶段时长、身份、库存、协议/物理/durable 计数及
首步/失败 attempt。端点未到达用 null；施力后必要工作超期为 miss_after_apply 并终止。
公开计时 sidecar 保存为输出根目录的 `.timing-<artifact-run-id>.jsonl`，位于严格正式 run
目录之外。最终返回的 cycle_summary 保留观测出口自身超期/记录失败的事实，资格判断
同时核验运行状态和该 summary，不能只取 sidecar 中的成功行。GUI 渲染不冒充设备确认。

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 10000 --segment-steps 400 --material-slots 16 --delay-ms 0 --output results/diagnostics/cycle-qualification.json
```

默认启动本机三进程、实际仿真循环和批量 writer；`--material-slots 0/4/16` 为显式对照。
已有真实三机角色监听时可加 `--role-config <Client配置>`，只运行 Client，不自动创建远端
角色；配置决定 TCP/mTLS，注入延迟此时仅作用于 Client 发送。报告保留 clock_info、
全部 cycle/阶段事件、startup jitter、失败、OS 内存、活动保存及停止 drain 成本。
qualification_pass 仅在完整 10k、零 miss、所有完整周期在 deadline 内且正常停止时成立；
一旦迟到即终止并保留失败证据。真实 Wi-Fi/硬件、不同网络尾延迟仍须实机验证。

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

### 倒立摆两测量动态有限 profile（#108）

Client 将 `configs/lab-client-continuous.example.yaml` 的 `experiment` 指向
`configs/cart_pole_observer_lan.example.yaml`；P1/P2 仍分别运行原脚本与角色配置：

```powershell
uv run python scripts/run_continuous_p1.py configs/lab-p1.example.yaml
uv run python scripts/run_continuous_p2.py configs/lab-p2.example.yaml
uv run python scripts/run_continuous_client.py configs/lab-client-continuous.example.yaml
```

三条命令需在不同终端启动，P1/P2 先监听。动态示例的 `numeric` 值是须由预检
接受的候选，不是算法常量；初始状态、首样本、编码位宽和范围证据在 Client 拨号前
统一生成。可选 `disturbances: [[200, 1]]` 表示第200区间的+1N单步外扰；它不进入
控制器输入。理想/安全各有独立 plant，终点仅观测。成功 JSON 的 `run_dir` 可用
`load_verified_cart_pole_run` 独立复核动态侧证据与图。失败时 CLI 只给受限故障类别、
已双提交数、已完成物理数和材料消耗；一次双提交不能当作施力完成。

本机三个 PID 可证明三独立进程，不证明真三机。`insecure_tcp` 无身份认证或传输加密；
需要该属性时选择现有 mTLS 配置。此有限入口仍按精确 N 步运行；同一 profile 的
动态持续入口见下节。数值、reader 和 `x̄_N` 交接详见
[观测器指南](cart_pole_observer.md)。

### 两测量动态持续运行（#109）

将 Client 的 `experiment` 指向 `configs/cart_pole_observer_lan.example.yaml`，
分别启动原 P1/P2，再运行
`uv run python scripts/run_cart_pole_client.py <Client 配置> --headless-continuous --segment-steps 400`。
Ctrl+C 请求正常停止；真实总步数可超过 profile 中用于有限实验的 horizon。
动态持续入口将同一 profile 重新预检为精确有理数的有界输入可达界，使用
`lan-segmented-v2`：一次离线分享、同一 session 和 controller epoch，段界仅用
双回执与 `segment_begin` 屏障，控制器秘密 state 不离开 P1/P2，材料和 round ID
逐全局步更新。现有静态持续 v1 与有限动态入口保留原行为。

正常停止且 reader、概要图和发布门禁全部通过后，headless 结果为 `complete`，
根目录的 format version 为 2。可用
`open_verified_cart_pole_segmented_run(run_dir)` 流式核对每段、全局控制器递推的
公开 nominal/Trunc 包络、独立理想 plant 和物理前缀。失败、取消、不确定提交或
进程崩溃留下 `.incomplete-<run-id>` 时，用
`open_verified_cart_pole_segmented_prefix(prefix_dir)` 核验 checkpoint、已封段和
未封段逐步日志；未封段没有双方结束回执，不是完整运行或可恢复控制状态。
任何方断连或重启都需要新的 run/session，不能从前缀自动续控。哈希链检测文件
不一致，不提供针对整体重写的密码学真实性。该证书证明控制器编码数值安全，
不保证非线性 plant 永久稳定、20 ms 墙钟或真实硬件。

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

动态 v2 可显式使用有限预送窗口。启动三方后，在倒立摆 Client 的 GUI 或
`--headless-continuous` 入口增加 `--preload-steps 1000 --preload-execution fused`
（可选 `staged`，段容量仍为 400）。GUI 与 headless 复用同一持续循环，库存耗尽
后正常封段、排空记录、核验并发布结果；第 1001 步不会现场生成或自动续送。
默认 `--preload-steps 0` 保留已有运行方式。该入口只支持动态 v2 同一 epoch，
不支持静态 v1、有限单段或 full v3。P1/P2 必须使用支持
`control-preloaded-v1` 的同版本程序，握手不匹配会直接失败。

材料在控制计时开始前逐轮生成和导出，每块至多 32 步及 128 KiB 原始本方数值，
通过原 schema 3 JSON 信封的规范 base64 传送；启动请求分别限制为 64 KiB
清单/封存和 256 KiB 块信封。整个预送阶段共用一个 startup timeout，不按块重置。
两方确认全部库存后才允许用新测量领取当前步。原材料导出即失去本地领取资格，
导出数量不算实际算术消费；接收方恢复当前轮的原 protocol 生命周期后才计算和提交。
缓存跨 400/800 段边界保留，断连、停止或异常后废弃剩余库存。

每主机材料编码预算为 8 MiB，包含缓存、2 MiB 临时编码副本、256 KiB 元数据与
512 KiB 当前轮额度；公开维度和模数在生成/分配前用于保守预检。临时界计入两方
块、base64/JSON/UTF-8/帧副本及当前生成对象，不是 Python 进程 RSS 上限。
观察报告分别给出原始缓存、实际应用帧字节和三个角色的 OS 峰值工作集。
预送期间与在线阶段均不运行旧材料生产线程；显式非默认材料池参数与预送互斥。

使用 `benchmark --case cycle --mode batch --steps 1000 --segment-steps 400
--preload-steps 1000 --preload-execution fused --output 新文件.json` 观察实际循环。
`staged` 普通轮 19 个应用帧，`fused` 普通轮 15 个应用帧，均保留双提交 ACK 和
7 个 peer 帧。`--delay-ms 1` 在每次应用帧发送前等待 1 ms，帧数改变会改变
注入等待总量，该观察不能解释为固定 Wi-Fi RTT。`stage_pass` 检查所请求阶段
全部周期无 miss；`qualification_pass` 仍要求完整 10000 步，1000 步窗口不能
据此宣称正式长跑资格通过。

动态记录器在原封段位置接管公开数据并计入原 8 MiB / 两段预算，等来源核查和
下一段握手完成后才放行当前批次。异常和正常停止均放行已接管数据进入原排空
流程；来源复核、可靠 checkpoint 和磁盘错误语义保持不变。结束、接管、来源、
握手和放行仍计入原绝对周期期限，失败样本也保留各实际执行阶段的时长；未执行
阶段不填零。观察报告分别列出控制线程与记录线程的来源复核累计时长和次数，
这些累计量不能当作某一次边界读取的耗时。

后台动态批次逐行校验规范编码与身份，使用最多 64 KiB 临时缓冲写出 journal、
原格式 spool 和计时 sidecar；保留完整哈希链读回、来源核验与批末同步/原子
checkpoint。缓冲不是新的逻辑段，可靠计数和原库存预算保持不变。每批公开起止
和嵌套阶段时长用于分析与控制周期的重叠；这些数据界不构成调度或耗时保证。

本机 `benchmark --case cycle --diagnostic` 可显式启用有限诊断（默认关闭）。
控制线程、记录线程及 P1/P2 分别保存同线程 `thread_time_ns` 与墙钟区间，
以及原正常 GC 的公开阶段/线程/代数事件；只观察首两轮及 global397…405。
记录批次按最后一个公开步骤定位，逐行校验按批汇总，不产生逐行诊断日志。
每角色共用最多512事件槽，事件编码最多72KiB，三角色诊断总编码最多256KiB；
槽位/编码截断均公开 overflow，缺失CPU时钟填null。正式记录8MiB/两段额度不变。
callback不写盘、不序列化、不查看对象；退出还原hook，不修改GC/调度设置。
重复阶段的首末时刻只是包络，内部有间隔；嵌套成本不可相加，wall−CPU仅为
综合未执行时间，不能直接解释为GIL、网络或磁盘。报告给出时钟实现/分辨率、
启动时钟读取探针和实际峰值RSS，测量开销仍计入原绝对20ms期限。
诊断允许单步请求，标记 `diagnostic=true`，不作为正式qualification资格。
当前获批观察仅为fused/stock1000/段400的零注入406步和1ms每帧1步，各一次；
失败即停，退出集中输出。未复现也不得循环追样本或用诊断PASS代替1000/10k验收。

- `configs/lab-p1.example.yaml`、`lab-p2.example.yaml`、`lab-client-continuous.example.yaml`：三个独立角色入口。
- `configs/local-deployment.example.yaml`：三条连接的地址和端口；三台电脑内容须一致。
- `configs/paper_pid_lan.example.yaml`：Client 日常参数，直接读取 `paper_pid_cascade_zoh.yaml` 和共享素数证明；不依赖 Fig3 四点定义，运行声明为 `user-exploration`。
- `configs/paper_pid_fig3_sweep.yaml`：四点图独占的冻结定义，仍读取历史名 `hvac_2r2c_sweep_prime.yaml`，因为已发布 Fig3 清单绑定文件名和原始 SHA。

旧 LAN/TLS 示例配置和 VS Code 调试清单已移除。历史 HVAC 配置仅留在 `tests/fixtures/legacy_hvac/` 供内部回归；它们不是日常实验入口。正式 `results/paper_pid_fig3/` 证据和四点 reader 保留。三角色与 Fig3 复用同一个 paper PID 场景计算，不复制安全协议。
