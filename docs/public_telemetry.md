# Client 公开遥测事件 v1

Issue #71 在仿真装配层的 Client 公开采样边界产生事件。`event_schema_version=1`
独立于实验 artifact v1 和 localhost wire v3。通用 `simulation.telemetry` 不知道 HVAC、PID、
socket、share 或协议资源。调用者可向 `simulation.runner.run(..., telemetry=session)`、
`engine.compare_closed_loops(..., telemetry=session)` 或无 ideal 的
`engine.run_secure_branch(..., telemetry=session)` 传入可选会话。默认执行和八字段结果不变。
`experiments.localhost_runner.run_localhost_comparison(..., telemetry=session)` 在真实
Client/P1/P2 路径上接入同一会话；其角色状态只来自调用前一次 `topology` 观察。

## 事件和数值

一个源会话从 `session_started` 开始，逐成功步产生 `sample`，失败时产生
`session_fault`，最后恰好一个 `session_ended`。公开 `session_id` 默认随机生成，与 wire
session/round/nonce 无关；`event_seq` 从 0 严格递增，**尝试入队前**分配。
`session_started` 含三组 `channels.reference/output/control.names/units` 和
`sample_time_unit="s"`，名称与单位按 index 一一对应。SISO 也使用长度 1 数组，向量信号不得
被 UI 当作单个温度标量。

`sample.step` 从 0 开始，`time_s` 是严格递增的仿真时刻，不是墙钟。
`reference`、`output_secure`、`control_secure` 是有限 1D 数组，其长度分别由上述三组通道
规定。`output_secure` 是 plant 更新前测量，`control_secure` 是场景 actuator 后实际送往 plant
的值。比较运行含 `output_ideal/control_ideal/control_error/output_error`，后两者逐通道严格为
ideal−secure，单位沿用 output/control。无 ideal 的 Client 单独运行四字段全部为 null，
不以 reference−output 冒充比较误差。成功样本只在 runtime 返回、actuator 和 plant.step
均成功后产生；失败步没有成功样本。只有完整 `SimulationResult` 验证成功才以
`status="completed"` 结束。

`roles` 始终列 Client/P1/P2，每项含 `state` 与 `source`。当前 localhost `topology.status`
是 session 状态投影，只有 `last_observed_ready/failed/closed/unknown`，不是独立实时心跳。
没有观察时为 `unknown/unavailable`。`latency_ms.controller_round` 用单调时钟覆盖
runtime.step，包含 IPC、双方计算、重构和提交；`actuator_plant` 覆盖场景施加控制和
plant.step。没有测量的 prepare/stage/commit 为 null。时延不进入控制律。

故障仅发布固定 `category`、step 和安全角色快照；不发布异常文本、路径、traceback、wire
payload 或诊断对象。`public_event_json()` 显式列出允许字段，公开日志也应使用此函数。
不能对事件对象递归 `asdict` 或记录原异常。可发布值不包括单方 share、triple、mask、
nonce、controller state 或 combined-share 诊断。遥测本身不做量化、截断或模运算，不构成
新的协议安全证明。

## 直播派发与接收

`BoundedPublisher` 在控制线程只做有限向量快照和立即入队；消费者回调在 daemon 线程执行。
队列满时丢最旧 `sample`，为生命周期/终态腾位；`dropped_samples` 记录损帧数。
消费者阻塞、断开或抛异常只改变 `delivery_failed`/展示帧，不能把控制成功改成失败，
也不能把派发成功冒充控制成功。控制路径不做 JSON、网络/磁盘 I/O、flush 或 join。
正式八字段轨迹不从有损队列回填。

接收者按 `(session_id,event_seq)` 去重；同一 ID 内容冲突视为契约错误，旧事件不覆盖
当前状态。跳号显示 gap，不插值控制值。晚加入者可先取得 `current_header` 和
`next_event_seq`；断连但未看到终态时显示 `unknown/disconnected`，不可推断 completed。
reset 是新公开会话和从 0 开始的新序列。

## 回放与边界

`experiments.telemetry_replay.replay_events(run_dir)` 先调用 canonical `load_artifacts`，
只接受已发布、hash/列/单位/时间/误差都通过复验的 v1 产物，再逐行映射同一事件契约。
回放的公开 ID 是 artifact 的 `run_id`。旧产物没有角色历史或阶段时延，所以这些字段
只能为 `unknown/null`；不能从 CSV 补造健康时间线。损坏或未发布产物无法回放。
直播有损，完整曲线以正式 artifact 为真值；当前普通 artifact 写入入口尚未关联新直播
session ID，因此若要跨入口关联，调用方须另行保存公开 ID 的 provenance。正式 artifact
发布若失败，运行报告必须标记 unavailable，不能展示为可回放。
