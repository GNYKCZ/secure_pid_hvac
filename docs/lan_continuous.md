# 独立三角色连续 LAN 实验（Issue #86）

此入口在一台电脑三个独立终端运行 paper-inspired PID 的连续安全闭环。三条连接
Client→P1、Client→P2、P2→P1 使用已有双向 TLS 1.3。P1/P2 只读角色配置、公开
数值 setup 与本方 share/资源；plant、PID 场景、明文测量及两份输出重构只在 Client。
本机实验不证明真实三台电脑的网络时延、采样周期或生产安全，也不宣称作者原 plant 的逐点复现。

## 本机启动

先按 [LAN 单步说明](lan_single_step.md)执行 `uv sync --locked`，并准备忽略目录中的短期
本机测试证书：

```powershell
uv run python scripts/prepare_local_lan_certs.py
```

在三个独立 VS Code 终端，从仓库根目录依次执行：

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
更新、两方 shutdown 回执、正式 reader 与图发布均成功后报告 run ID/目录。退出码与
单步入口相同；失败只输出受限类别/异常类型，不打印 frame、share 或私钥。任一回执
不确定时须停止三方并重新启动，新 session 产生全新资源；`reset` 不在原连接上可用。

## Client 实验配置

`configs/local-client-continuous.example.yaml` 的 `experiment` 指向
`configs/paper_pid_lan.example.yaml`。P1/P2 的 YAML 没有场景字段；三方仍引用同一
topology，各自仅拥有本机证书与私钥路径。实验 profile 允许修改：

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

## 结果、图与重绘

正式 `trajectory.csv/config.json/metadata.json` 保持八字段 v1。`control_ideal` 与
`control_secure` 是 actual applied 控制量；当前恒等 actuator 使 raw=applied，单位
`paper_unit_unspecified`。同批发布的 `control.png` 有三栏：上为 `u(t)`、中为
`û(t)`，两栏共享同一纵轴范围和刻度；下为有符号 `u−û`，共享秒时间轴。
`control_plot.json` 绑定 run ID、CSV/config/图摘要、通道与样本数。reader 会复验附加文件；
图生成失败没有可读为 success 的 run 目录。`reference=unused_zero` 只是 schema 占位，
不是设定值阶跃。

仅从已验证结果单独重绘，不启动协议：

```powershell
uv run secure-control redraw --run-dir results/lan_continuous/<run-id> --output results/lan_continuous/redrawn.png
```

自动拉起三个本地角色的 localhost 后端仍用于固定 seed 的数值/消息诊断；本入口验证
独立命令和 mTLS 连续 session。两者复用 `Protocol3Orchestrator`、`_complete_client_round`
与八字段 reader，不复制乘法、Trunc 或场景特化协议。#68 旧单步命令与 wire 语义保留。
