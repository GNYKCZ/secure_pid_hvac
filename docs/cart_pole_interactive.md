# 倒立摆动画 Client：三角色快速操作

## 无证书两机非实时动态演示

本次推荐使用已合并矩阵后端的 `control-dynamic-matrix-v1`，保留原两测量observer、约5°初态、20 ms模型步长和秘密分享计算。
显式 `--non-realtime` 取消本次演示的采样周期截止要求；省略它仍执行原20 ms绝对截止检查。
墙钟慢于20或40 ms不会单独导致失败，没有速度指标。每个已双提交并完成仿真确认的步骤才推进20 ms仿真时间。
快机器尽力按相邻实际采样间隔至少20 ms展示；慢时不追赶、不跳步、不积压旧测量。
启动、通信、空闲和关停仍有原秒级超时；材料短缺、非法消息、断连或缺提交回执仍停止，不重试未知轮。

两台电脑使用同一版本代码和Python 3.11，各在仓库根目录执行 `uv sync --locked`。
A运行Client、软件plant、动画及自动管理的材料worker；B运行P1/P2两个独立进程。
无证书TCP没有身份认证或信道加密，能观察两份share的网络观察者可能恢复秘密；P1/P2同机也不提供独立服务器隔离。
这里只用于可信隔离网络上的软件演示，不是论文安全部署或真实设备实时控制。

两台的 `configs/local-deployment.example.yaml` 填入相同内容。下面IP **必须换成B的实际局域网IPv4**：

```yaml
version: 1
identities:
  Client: client.secure-control.test
  P1: p1.secure-control.test
  P2: p2.secure-control.test
p1_client:
  bind: 192.168.31.253
  host: 192.168.31.253
  port: 34401
p2_client:
  bind: 192.168.31.253
  host: 192.168.31.253
  port: 34402
p1_peer:
  bind: 127.0.0.1
  host: 127.0.0.1
  port: 34403
```

B允许A访问TCP 34401/34402；34403只供B本机P2连接P1，A无须监听。
网络需允许设备互访，不用生成或分发证书。在B的 `configs/lab-p1.example.yaml` 使用：

```yaml
role: P1
transport: insecure_tcp
wire_profile: control-dynamic-matrix-v1
topology: local-deployment.example.yaml
timeouts:
  startup: 180
  step: 30
  shutdown: 5
```

B的 `configs/lab-p2.example.yaml` 内容相同，只把 `role` 改为 `P2`。
A的 `configs/lab-client-cart-pole.example.yaml` 使用下面内容，**不要改水箱使用的lab-client-continuous配置**：

```yaml
role: Client
transport: insecure_tcp
wire_profile: control-dynamic-matrix-v1
topology: local-deployment.example.yaml
experiment: cart_pole_observer_lan.example.yaml
timeouts:
  startup: 180
  step: 30
  idle: 30
  shutdown: 5
```

timeout单位是秒，`step: 30`不是30 ms。三个角色wire必须一致，不能只改Client。
transport与wire独立；省略wire仍是原 `control-batch-v1`，不会自动升级协议或关闭实时保护。
本轮没有改您已有部署配置或示例默认，请在三份角色配置中手工选择同一wire。
旧 `control-dynamic-compact-v2` 仍可用；恢复旧演示时三角色都恢复原wire及所需场景。

依次启动，每个命令占一个独立终端。B的终端一：

```powershell
uv run python scripts/run_continuous_p1.py configs/lab-p1.example.yaml
```

B的终端二：

```powershell
uv run python scripts/run_continuous_p2.py configs/lab-p2.example.yaml
```

A在180秒启动等待内运行：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole.example.yaml --non-realtime --recording light --segment-steps 400
```

窗口标注“非实时仿真，模型步长20 ms”，仿真时间、确认步数与墙钟时间分开。
左右键/按钮仍施加±1 N、一个20 ms仿真区间的扰动（±0.02 N·s），观察恢复/稳定状态。
400步是段容量而非总步数上限；满段维护后沿同一秘密observer状态继续，不重置x0。
点击“停止”完成在途轮与双方停止确认；关窗是取消。正常停止可仍处于recovering，不保证末态stable。
light不保存完整轨迹，不能正式回放或声称完整实验已保存。断连、失败或再次演示时重启三方，不恢复旧session/材料。

无窗口时A使用同一后端，以Ctrl+C请求正常停止：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole.example.yaml --headless-continuous --non-realtime --recording light --segment-steps 400
```

非实时摘要写明transport、wire、material_source、timing_mode=`non_realtime_demo`、model_period_s、墙钟耗时和实际尝试/提交/物理确认数。
没有CycleTiming时misses/last_cycle和近期分位为null，表示不适用，不是零超期或零耗时通过。
当前compact-v2、matrix-v1或`--non-realtime`只支持动态持续light；与静态、finite、预送、full记录及完整安全起摆组合均在联网前拒绝。
旧batch/full和实时功能保持。`--full-non-realtime`属于另一完整路线，不替代本选项。
本入口直接装配通用runtime，不经过受限network benchmark，不放宽其TLS/来源/额度门禁，也不复用#128已消费的P0/A/B预算。
本轮只做短软件功能检查；真实两机功能和性能待用户设备验证，本机三进程不冒充跨机验收。

### 原20 ms截止模式与结果提取

先确认三个角色的最终JSON标识实际使用 `insecure_tcp`，Client还应为
`wire_profile=control-dynamic-matrix-v1`、`material_source=worker`。
控制方程、矩阵材料、双提交和原模型0.02s均保留；取消TLS只影响信道加密/身份认证。
两台电脑请用同一PR整合后的完整提交，旧PR125或只含矩阵核心的main不能替代此入口整合。

需要观察原截止模式时，重启B的P1/P2，再在A省略 `--non-realtime`：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole.example.yaml --headless-continuous --recording light --segment-steps 400
```

此时 `timing_mode=absolute`，周期从计划采样起点计算，包含仿真设备确认、记账及跨段维护。
任何超期沿原规则停止；不是把本次已批准演示改成40 ms控制。需要动画时只去掉
`--headless-continuous`，GUI与headless使用同一后端；窗口刷新率不能当作控制周期。

headless结束时输出一行JSON；Ctrl+C请求正常停止，先等最终JSON和双方停止回执，再重启三个角色。
如需保存原始摘要，可先创建本机临时输出目录并用PowerShell保存stdout（下例仍是截止模式）：

```powershell
New-Item -ItemType Directory -Force .tmp | Out-Null
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole.example.yaml --headless-continuous --recording light --segment-steps 400 | Tee-Object -FilePath .tmp/cart-pole-client.json
$demoResult = Get-Content .tmp/cart-pole-client.json -Raw | ConvertFrom-Json
$demoResult | Select-Object status, transport, wire_profile, material_source, timing_mode, model_period_s, confirmed_step_count, protocol_committed_count, failure_phase, category
$demoResult.cycle_summary | Format-List
$demoResult.recording_summary.recent_timing | Format-List
$demoResult.material_summary | Select-Object encoding_profile, claimed, generated_received, worker_exited, receiver_exited, credit_thread_exited, cleanup_failed, error_type
```

`cycle_summary`是全程尝试/超期计数；`recording_summary.recent_timing`只覆盖最近最多256条中
有完整端点的周期，不是全程分位。未完成端点不补零，`final_failure`保留最后失败；
非实时模式没有CycleTiming，因此这些分位为null，墙钟平均耗时也不能替代它们。
比较速度前先核三角色同版本、同wire、同模式、相同输入和网络条件，并记录实际运行SHA；
本次不预先承诺两机20/15/40 ms，也不强制您做TLS对照。

默认窗口持续运行，点击“停止并保存”提交正常停止请求。段容量由
`--segment-steps 400` 指定（允许 1…1000），总步数由实际停止时的双方确认前缀决定，
不会在第 400 步自动结束。保留显式 `--finite` 的原 400 步有限窗口。
需要仅运行 #100 的无 GUI 后端时，可使用：
`uv run python scripts/run_cart_pole_client.py --headless-continuous --segment-steps 400`。
先分别启动原 P1/P2；它们会在同一次启动中服务后续段。静态 profile 的 headless
入口返回双方确认的 `stopped` 与准确步数，不产生正式长轨迹结果。两测量 observer
profile 使用 #109 动态 v2，同一 session 跨段续算；正常停止并验证发布后返回
`complete` 和正式结果目录，故障时返回可核验的未发布前缀路径。
`--finite` 与 `--headless-continuous` 互斥。生命周期 API、失败计数与回调见
[持续分段后端](lan_continuous.md#持续分段后端100)。

这是近直立仿真。默认初态约为 5°，每个控制区间对应 **20 ms 仿真时间**；窗口帧率及网络墙钟时间不保证 20 ms。真实三电脑和硬实时能力尚未实测。本机三进程回归包含明文 TCP 与 mTLS，不能替代真实三机验收。

## 本机三终端

在相同仓库和 `uv.lock` 环境中，依次开三个终端：

```powershell
uv run python scripts/run_continuous_p1.py
uv run python scripts/run_continuous_p2.py
uv run python scripts/run_cart_pole_client.py
```

也可在 VS Code 中直接对 `scripts/run_cart_pole_client.py` 使用“运行 Python 文件”，无需修改脚本。窗口先显示初态/待连接，随后按实际 Client 阶段显示连接中、双方已连接、运行中、普通支重放、验证/保存及完成或失败。P1/P2 的 `closed` 不单独表示 Client 成功。

运行中按左/右方向键或点击按钮，请求 −1/+1 N 的水平小车外力，持续**一个控制区间**，等效冲量 ±0.02 N·s。点击仅表示排队；Client 在安全控制步双提交、控制器力裁剪后、plant 前锁存，实际步号由正式证据记录。队列满、取消或合力超出 ±10 N 时拒绝；不会悄悄裁剪外力。状态的 `recovering/stable` 沿用 #91 的四维观测判据。若越工作域、失稳、断连或关窗，运行失败且不能把未验证结果称为成功；重试需重启三个角色以取得新 session/材料。

运行时“已提交”画面只来自协议和物理均确认的安全支。停止请求立即拒绝新外力，
在途区间沿原门禁完成；停止处理中保留最近确认画面，不预报最终 N。
关窗属于取消，不等同于正常停止。后端停止后，窗口显示独立对照重放、验证、绘图、
发布阶段；双方 `closed` 不足以显示完整完成。停止时 recovering 或 stable 都如实记录。

完成后窗口显示结果目录，滑块及整数跳转支持实际第 0…N 个观测。读取在后台执行，
旧跳转不会覆盖新选择，最多缓存两块；第 k>0 个观测的施力来自上一区间 g=k−1，
第 0 个观测不伪造控制力。按钮打开同一 run 的 `control.png` 与 `cart_pole_motion.png`。
两图是固定 2048 桶的首/末/min/max 概要，逐步原值始终保留在数据块及精确回放中。
默认输出在 `results/lan_continuous/<run-id>/`。

静态持续结果使用独立 `cart_pole_segmented_run` format v1：根 `run.json/config.json`、
有序摘要链 `segments.jsonl`、各段 `protocol.json`，以及 n>0 段的 canonical 八字段 v1
数据块和倒立摆 v3 侧证据。完整 reader 从唯一初态连续复核两支、事件、跨段 monitor、
身份/资源及双回执；最后 0 步 stop 段保留回执但没有空 CSV 或虚构 SimulationResult。
分段数据块的 scope 是 `segment_fragment`，单块成功不表示整个 run 完成。
正式根仅在 reader、两图和取消门禁均通过后原子发布；磁盘不足、源变化或任何处理失败
不会发布完整成功。摘要/回执是原 Client 来源信任下的一致性证据，不是签名证明。
动态 v2 结果在相同根结构中另存逐步 journal 和原子 checkpoint；失败前缀由
`open_verified_cart_pole_segmented_prefix` 读取。#109 验证的动态仿真入口是 headless；
窗口的动态阶段/交互全集仍归 #103。

```python
from secure_control.experiments.cart_pole_segmented_evidence import (
    open_verified_cart_pole_segmented_run,
)
run = open_verified_cart_pole_segmented_run("results/lan_continuous/<run-id>")
print(run.metadata["N"], run.observation_at(run.metadata["N"]))
for entry, record, evidence, protocol in run.iter_segments():
    # 流式消费当前块，勿收集为全 run 数组。
    print(entry["index"], entry["global_start"], entry["global_end"])
```

`--finite` 保留旧 v1/v2 证据、exact-N 和末端 stable 要求，仍从
`cart_pole_evidence.json` 回放 0…400。通用重绘命令也识别新的完整聚合根：
`uv run secure-control redraw --run-dir <run-dir> --output <new-control.png>`。
它先完整验证，再流式绘制概要，不启动安全协议。
重绘目标必须是正式源目录之外的新文件；已有目标以及通过目录别名指向源内的目标
均在写入前拒绝，原结果的图摘要、目录成员及回放能力保持不变。

## 三电脑配置

三台电脑使用同一代码和锁文件，将 `configs/local-deployment.example.yaml` 的三条地址与固定端口改成可互访的机器地址，并在三台上保持内容一致；P1/P2 分别运行现有脚本，Client 以自己的一份角色配置路径运行 `uv run python scripts/run_cart_pole_client.py <client-config>`。Client 配置指向本机可读的倒立摆 experiment profile；各角色的 topology、传输模式和证书设置必须与现有 [LAN 说明](lan_continuous.md)一致。示例 `insecure_tcp` 只适合可信隔离实验网，**没有身份认证或传输加密**；需要认证时使用项目已有 mTLS 配置。本 Issue 未在真实三台电脑上验证连接、身份或延迟，不能把本机三进程运行视作三机验收。
