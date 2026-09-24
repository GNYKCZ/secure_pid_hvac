> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# localhost 通信传输

Client 公开运行状态与采样遥测在仿真装配层产生，不改变本 wire 契约；角色 `topology`
仅是 session 状态投影。见 [公开遥测事件 v1](public_telemetry.md)。

Issue #17 增加显式选择的 `LocalhostSecureStateSpaceRuntime`。它仍向 simulation 提供
`step(v) -> ndarray(p,)` 与 `reset()`，默认 `SecureStateSpaceRuntime` 不变。此后端只模拟本机
TCP 消息传输，不提供 TLS、身份认证、多机部署或生产安全保证。

## 拓扑与可见性

父进程 supervisor 在字面量 `127.0.0.1` 上建立一个 listener，再用 Windows 兼容的 `spawn`
启动 Client、P1、P2 三个不同 PID。Client 另经两条私有 loopback 连接分别向 P1/P2 发送单方
controller、state、input 和一次性资源 share，并接收各自的 control share；supervisor 不接收
这两份原始 share。

Issue #66 将在线 P1/P2 消息改为专用全双工 loopback TCP 通道：P1 监听、P2 连接，并在启动时用
一次性 nonce 确认角色。Issue #67 将唯一的 `protocol.coordinator.Protocol3Orchestrator` 放在
Client 进程中运行；父进程每轮只发送一次 `step` 请求并接收双角色提交后的公开结果。
Client 经私有通道发送单方在线材料和不带 share 的 `endpoint` command，接收各方暂存回执与
各自的 control share。每个 Protocol 1 资源由 P1/P2 双向交换
`ProductMaskPayload`；Protocol 2 只发送 P2→P1 的 `P2TruncationPayload`，不发送 P1 的截断
masked share。localhost worker 只负责 Client 编排、framing、严格 codec、单条 command 分派和清理；
矩阵遍历、Beaver/Trunc 顺序及资源生命周期仍由 protocol 层拥有。nonce 只用于避免启动串线，
不能视为密码学认证。

## Wire 契约

- schema version 固定为 `3`，未知版本直接失败，不协商降级；v2 的父进程逐阶段调度信封不可混用；
- envelope 明确 kind、sender、recipient、单调 sequence、operation、session、round、step 与
  resource identity，并拒绝未知、重复、缺失字段和非法组合；
- payload 为 canonical UTF-8 JSON 的固定类型 union，不使用 pickle、`eval` 或动态类型导入；
- P1/P2 peer 信封另验证严格方向、单调 sequence、session/round/step/resource identity 和
  operation/payload 组合；超时、断开或错序会使整个 session fail closed；
- 任意精度整数使用 canonical 十进制字符串，object array 使用 shape 加扁平整数列表，无 float
  或 fixed-width integer 转换；普通浮点数组只允许有限实数；
- TCP frame 为 4-byte network-order 无符号长度加 payload，默认上限 8 MiB，先验证长度再读取；
- JSON 深度、字段数、数组元素数、整数位数和 frame 大小均有固定预算。

transport-safe offline/online material 只包含单方数值 share 和不可变 identity。接收角色在 protocol
边界建立本地 owner/lifecycle；wire 和 execution codec 都不能提供或恢复远端声明的消费状态。
在线状态依次为 `READY(k) → PREPARED(k) → STAGED(k) → RECONSTRUCTED(k) →
COMMITTING(k) → READY(k+1)`。Client 先确认两方暂存与重构，再按 P1、P2 顺序确认提交；
只有两份提交回执都通过，才返回公开输出、round/step 和资源计数。父进程看不到资源计划、
endpoint command、两份原始 share 或任一单方提交回执。任一在线错误、断开、超时或提交回执
不确定均进入失败状态，不能在旧 session 重试；`reset()` 才建立新的三角色 session。

## Timeout、失败与生命周期

`LocalhostTimeouts` 分别配置 startup、step 和 shutdown。每次 socket 收发使用
`time.monotonic()` 绝对 deadline，因此 TCP 分片不能靠逐字节到达反复刷新 timeout。空帧、超长帧、
截断帧、非法 JSON、错误角色/顺序/identity、disconnect 和远端异常都会 fail closed：整组三角色
连接和进程被有界关闭，不在提交状态不确定时自动重连或继续旧 session。

正常 `close()` 由父进程请求 Client 关闭，Client 再经私有通道关闭 P1/P2；异常时父进程有界终止整组。
`reset()` 复用 supervisor listener，先让 replacement trio 完整 ready，再替换旧 session；启动失败
时旧 session 仍可使用。`close()` 幂等，关闭后释放 listener 端口。`topology` 只公开 loopback
host/port、角色 PID 和状态；`resource_counts` 只统计成功提交的逻辑资源。

## 使用与对照

```python
from secure_control.execution import LocalhostSecureStateSpaceRuntime

with LocalhostSecureStateSpaceRuntime(
    spec,
    fixed_point,
    range_contract,
    security_parameter=8,
) as runtime:
    output = runtime.step(controller_input)
```

使用同一配置和测试 seed 与 Issue #16 multiprocessing 后端比较 180 步 HVAC：

```powershell
uv run python -m secure_control.experiments.localhost_runner `
  --config configs/hvac_dual_loop.yaml --seed 905
```

JSON 摘要只包含 host/port、PID、样本数、最大数值差异、资源计数与清理状态，不包含 frame、share、
triple、mask 或 controller state。`test_seed` 只复现实验材料；bootstrap nonce 不从该 seed 派生。

## 声明边界

此实现证明的是同机三进程和显式 localhost 传输路径的实验隔离。它不抵抗同机恶意进程、串通、
流量分析或 side channel，也不承诺跨版本、跨语言、Internet 或生产环境兼容性。
