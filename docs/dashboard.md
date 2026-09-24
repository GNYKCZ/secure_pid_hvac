# Client 本机只读 Dashboard（Issue #72）

本页面只绑定 `127.0.0.1`，应在 Client 电脑启动。直播消费 [A07 公开遥测 v1](public_telemetry.md)，
回放先由 canonical `load_artifacts` 验证完整的正式八字段结果，再由 `replay_events` 映射为同一事件。
页面只画来源数值，不重新运行仿真，不重算 ideal−secure，不读取 P1/P2 目录或私有诊断文件。

## 启动

从仓库根目录执行 `uv sync --locked`，再任选一条命令。所有配置、精度、seed 与输出路径均由
CLI 决定；页面没有运行、参数修改、协议命令或失败重试入口。默认端口 8765；`--port 0`
可让系统选择空闲端口。启动后打开终端打印的本机 URL。

```powershell
uv run python -m secure_control.experiments.dashboard replay-paper-sweep
uv run python -m secure_control.experiments.dashboard replay-run --run-dir results/csv/<run_id>
uv run python -m secure_control.experiments.dashboard live-hvac --config configs/hvac_2r2c_dual_loop_25_20_15.yaml --output-root results/diagnostics/dashboard_hvac --seed 42
uv run python -m secure_control.experiments.dashboard live-paper --ell 32 --config configs/paper_pid_fig3_sweep.yaml --output-root results/diagnostics/dashboard_paper --seed 70
```

直播命令先启动页面；在终端按 Enter 后仅运行一次控制。自动化可把
`--start-immediately --hold-seconds 20` 放在子命令前。Ctrl+C 停止本机页面；它不向控制器发送命令。
`replay-paper-sweep` 先用 #70 的 `render_saved_sweep` 复验四点清单和图，再逐个开放正式 run。
已提交的四点是 `single_process` 的 paper-inspired 结果，不是三角色直播历史。
`live-paper` 只产生一个所选精度的 `localhost` 三角色 run，不自称四点扫描。

直播页可丢帧；每个浏览器有自己的有界缓冲和写超时。页面慢读、关闭或断开时，正式八字段结果
仍由同一次控制计算在内存中发布，绝不从直播队列回填。只有 writer 发布且 reader 再次验证成功，
状态才变为 `verified` 并出现“回放所选 run”。新 run 的公开 provenance 保存
`public_telemetry_session_id`，可核对该次直播与正式 run；旧 run 只标作保存回放。
控制完成但正式发布失败时状态为 `unavailable`，不能据 A07 的 `completed` 推断已有文件。

## 数据和显示语义

- `sample.step` 从 0 开始，`time_s` 是仿真秒而非墙钟。输出为 plant 更新前的测量；
  `control_ideal/control_secure` 是场景 actuator 后实际施加的控制。HVAC 不得据此反推 raw 控制。
- 曲线名称和单位逐通道来自 `session_started.channels`。向量信号要求显式选择 index；
  reference 与 output 仅在名称语义可对应且单位相同的情况下共轴。`unused_zero` 是未使用的
  schema 占位，页面明确不把它画成设定值或阶跃。
- 控制图始终分别画原始 `u(t)=control_ideal` 与 `û(t)=control_secure`；有符号控制误差
  `u−û=control_error` 另图显示。#70 恒等 actuator 的 `raw_equals_applied=true` 仅适用于
  该 verified paper run。paper PID 的 `paper_unit_unspecified` 显示为“物理单位未指定”，
  51 点对应 k=0…50、0…5 s；不能据此声称作者原 Fig. 3 的逐点复现。
- 无理想分支时四个 comparison 字段全为 null，页面只画 secure 侧。旧回放的角色与阶段时延
  是 unknown/null。直播角色只是最近的 `session_topology` 快照，不是独立心跳；仅非 null 的
  `controller_round` 与 `actuator_plant` 以毫秒显示，prepare/stage/commit 标为未采集。
- `(session_id,event_seq)` 供页面去重、拒绝迟到事件和检测 gap。缺帧不插值；正式回放提供
  完整轨迹。连接断开且无终态时显示“运行状态未知”，不推断控制成功或失败。

## 公开字段与边界审查

HTTP 只有固定静态资源、`GET /api/status`、`GET /api/events` 和对 CLI 允许 run ID 的
`GET /api/runs/<run_id>/events`。其他方法与路径拒绝；`Host` 只接受该 loopback 端口的
`127.0.0.1` 或 `localhost`，无 CORS 放行、外部脚本或字体。浏览器不能提交任意文件路径。
SSE 仅调用 A07 的 `public_event_json()` 白名单；状态仅含公开 session/run ID、场景、backend、
精度、reference/raw-applied 声明、发布状态和投递损帧计数。来源名称与单位通过 DOM 文本节点
插入，不作为 HTML。服务不输出配置全文、异常文本、share、mask、nonce、triple、
combined-share 或诊断路径。

固定测试 seed 仅用于诊断复现。localhost 是同机三角色模拟，不代表认证 LAN、真实三机持续运行
或生产安全部署。Dashboard 也不提升论文安全证明或 paper-inspired 对作者原实验的声明等级。
