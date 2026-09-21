# 多进程安全执行

Issue #16 增加可显式选择的 `MultiprocessingSecureStateSpaceRuntime`。它保持
`ControllerRuntime` 的 `step(v) -> ndarray(p,)` 与 `reset()` 契约，不改变默认的
`SecureStateSpaceRuntime`，也不改变 simulation/result 接口。

## 进程与数据边界

运行时固定使用 `multiprocessing.get_context("spawn")`，为 Client、P1、P2 建立三个持久、
互不相同且不同于父进程的 PID：

- Client 持有明文 `ControllerSpec`、明文输入、预处理材料生成能力和最终输出重构能力；
- P1/P2 各自只接收本方 controller、state、input、Beaver 与 Trunc share；
- P1/P2 通过私有 Pipe 交换现有 Protocol 1/2 的遮蔽消息；
- 父进程只传递公开 session/round/step、操作状态和最终解码输出，不接收原始双方份额。

IPC 使用固定版本的不可变信封，并逐项校验 request、role、operation、session、round、step 和
resource id。它是本机进程适配协议，不是 Issue #17 的网络 wire schema，也不提供网络认证。

## 生命周期

```python
with MultiprocessingSecureStateSpaceRuntime(
    spec,
    fixed_point,
    range_contract,
    security_parameter=8,
) as runtime:
    output = runtime.step(controller_input)
```

`ProcessTimeouts` 为启动、单步和关闭提供有限正数上限。工作进程错误、响应错配或超时会使当前
session fail-closed；运行时立即有界终止整组三个进程，不会在提交状态不确定时继续下一步。
`reset()` 先完整启动新三进程 session，再替换并关闭旧 session。`close()` 可重复调用；上下文
管理器始终在退出时清理进程。

`topology` 只公开角色、PID、`spawn` 和状态；`resource_counts` 只累计成功提交步骤消耗的逻辑
乘法/截断资源数。原始 share、遮蔽随机量和 controller state 不属于公共诊断接口。多进程后端
不支持单进程诊断 trace。

## HVAC 比较入口

HVAC 仅增加一个 runtime builder 注入点，默认仍构造单进程后端。比较入口显式注入多进程后端：

```powershell
uv run python -m secure_control.experiments.multiprocessing_runner `
  --config configs/hvac_dual_loop.yaml --seed 901
```

命令输出 JSON，包含三个角色 PID、启动方式、样本数、单/多进程最大控制与输出差异、资源计数、
清理状态和安全边界摘要。入口使用 `freeze_support()` 和 `if __name__ == "__main__"`，导入模块
不会启动任何子进程。
