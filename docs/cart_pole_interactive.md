# 倒立摆动画 Client：三角色快速操作

## 无证书两机非实时动态演示

本次推荐使用已合并矩阵后端的 `control-dynamic-matrix-v1`，保留原两测量observer、约5°初态、20 ms模型步长和秘密分享计算。
显式 `--non-realtime` 取消本次演示的采样周期截止要求；省略它仍执行原20 ms绝对截止检查。
墙钟慢于20或40 ms不会单独导致失败，没有速度指标。每个已双提交并完成仿真确认的步骤才推进20 ms仿真时间。
快机器尽力按相邻实际采样间隔至少20 ms展示；慢时不追赶、不跳步、不积压旧测量。
非实时节拍使用标准库 `time.sleep`，按同一“上次实际采样+模型周期”目标分片等待，
每次请求最多5ms，返回后检查停止/取消并重算剩余时间；不忙等、不改变系统定时设置。
取消从事件唤醒改为片段返回后检查，5ms不是系统调度保证；严格模式不变。
这是减少等待粗化的候选，实际收益尚待两机报告中的等待偏差、采样间隔与工作耗时确认。
矩阵编解码直接处理任意精度整数，减少逐元素临时份额包装；最终矩阵份额、截断与校验保留。
通信字节和协议不变，帧数/往返数不减少，命令和配置无需修改；本地处理收益仍待实测。
规范不可变的矩阵资源计划校验直接比较完整截断元数据，省去本地递归复制和JSON比较；
其他输入保留原校验语义，计划摘要和网络编码不变，实际提速尚待两机测量。
矩阵掩码加减在完整检查后，让标准Python整数object数组复用原模运算内核，减少重复校验副本；
其他表示沿用通用接口，输入隔离和材料一次性规则不变，本轮收益未测。
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
网络需允许设备互访，不用生成或分发证书。仓库已经配齐下列专用配置，直接使用，不必再手工添加wire、修改experiment或删除TLS字段：

| 机器 / 角色 | 已配好的角色文件 | 固定选择 |
| --- | --- | --- |
| A / Client | `configs/lab-client-cart-pole-demo.example.yaml` | 无证书TCP、matrix-v1、两测量动态observer |
| B / P1 | `configs/lab-p1-cart-pole-demo.example.yaml` | 无证书TCP、matrix-v1 |
| B / P2 | `configs/lab-p2-cart-pole-demo.example.yaml` | 无证书TCP、matrix-v1 |

三份文件共用 `local-deployment.example.yaml`；下载后唯一需要按机器填写的文件就是上述拓扑，
填好后将**同一份**文件复制到A/B的configs目录。不要把某台机器的私有IP当作所有下载者的默认地址。
若已有本机拓扑可继续使用，P1/P2同机时peer也可填B的本机可达地址，但A/B文件内容须完全相同。
timeout单位是秒，`step: 30`不是30 ms。

**必须使用下面命令里的完整配置路径。**通用 `lab-p1.example.yaml` / `lab-p2.example.yaml`
及不带配置参数的P1/P2启动保留原batch默认，供paper PID等旧实验使用，不能与本套matrix Client混用。
原 `lab-client-cart-pole.example.yaml` 是静态反馈/旧路线配置，不是本套动态演示；已有本机修改也不会被此专用配置覆盖。
transport与wire独立；省略wire仍是原 `control-batch-v1`，不会自动升级协议或关闭实时保护。
本套演示仍需显式传 `--non-realtime`，不会把原20 ms检查悄悄关闭。旧compact-v2保留，但不需要为本套演示再选它。

依次启动，每个命令占一个独立终端。B的终端一：

```powershell
uv run python scripts/run_continuous_p1.py configs/lab-p1-cart-pole-demo.example.yaml
```

B的终端二：

```powershell
uv run python scripts/run_continuous_p2.py configs/lab-p2-cart-pole-demo.example.yaml
```

A在180秒启动等待内运行：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-demo.example.yaml --non-realtime --recording light --segment-steps 400
```

窗口标注“非实时仿真，模型步长20 ms”，仿真时间、确认步数与墙钟时间分开。
左右键/按钮仍施加±1 N、一个20 ms仿真区间的扰动（±0.02 N·s），观察恢复/稳定状态。
400步是段容量而非总步数上限；满段维护后沿同一秘密observer状态继续，不重置x0。
点击“停止”完成在途轮与双方停止确认；关窗是取消。正常停止可仍处于recovering，不保证末态stable。
light不保存完整轨迹，不能正式回放或声称完整实验已保存。断连、失败或再次演示时重启三方，不恢复旧session/材料。

无窗口时A使用同一后端，以Ctrl+C请求正常停止：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-demo.example.yaml --headless-continuous --non-realtime --recording light --segment-steps 400
```

非实时摘要写明transport、wire、material_source、timing_mode=`non_realtime_demo`、model_period_s、墙钟耗时和实际尝试/提交/物理确认数。
没有CycleTiming时misses/last_cycle和近期分位为null，表示不适用，不是零超期或零耗时通过。
当前compact-v2、matrix-v1或`--non-realtime`只支持动态持续light；与静态、finite、预送、full记录及完整安全起摆组合均在联网前拒绝。
旧batch/full和实时功能保持。`--full-non-realtime`属于另一完整路线，不替代本选项。
本入口直接装配通用runtime，不经过受限network benchmark，不放宽其TLS/来源/额度门禁，也不复用#128已消费的P0/A/B预算。
本轮只做短软件功能检查；真实两机功能和性能待用户设备验证，本机三进程不冒充跨机验收。

### 每步性能观察与结束报告（#132 阶段A）

动态持续light默认启用 `--performance summary`。沿用上面的三份demo配置和启动命令，
P1/P2不增加参数；Client窗口新增带实际步号的性能文字和最多256步的工作耗时趋势。
动画仍约40ms轮询，性能最多每100ms刷新；界面可以合并，后台仍统计每个尝试。
趋势纵轴0–60ms，超出范围只在图上截顶，文字与报告保留真实值。

四个口径独立：施力耗时从实际采样到双提交、plant推进及confirm_applied返回；
完整工作还包括本步记账和应归本步的自动段尾维护；采样间隔是两次实际采样的距离；
主动等待记录请求值、实际耗时和正常到期后的超出值。首步间隔和未到达端点为null。
非实时满段维护虽然在下一循环顶部执行，仍归刚填满段的上一控制步，不移动实际操作。
启动、正常停止和worker清退另列。`stage`是通信与服务器处理的合计，不能叫纯网络RTT；
维护总计与maintenance_*、commit与各party细项有包含关系，不能相加。

全程次数/总和/均值/min/max及完整工作>15ms、>20ms参考计数精确累计；
P50/P95/P99为全程固定0.1ms桶的nearest-rank区间，超过1000ms报告下界且上界null。
每个指标都有自己的count和missing_count，失败端点不补零；控制失败/不确定/取消仍单独报告。
旧 `cycle_summary` 与 `recording_summary` 含义不变，非实时仍没有强制deadline或miss结论。
观察在Client本机perf_counter_ns域采样，不跨电脑相减绝对钟。

非实时GUI采样并保存前10000次观察的命令如下，输出必须是不存在的新JSON文件：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-demo.example.yaml --non-realtime --recording light --performance samples --performance-sample-limit 10000 --performance-output results/diagnostics/cart-pole-timing-01.json
```

`10000`只是记录容量，满后继续控制并继续全程汇总，原始样本明确标记不完整；
它不安排10000步实验、不自动停止、不补跑。加 `--headless-continuous` 使用相同后端，Ctrl+C正常停止。
GUI点击“停止”结束，关窗沿原取消流程；强杀/掉电可能丢失内存统计。
使用 `--performance off` 可关闭新增观察；full/finite/完整起摆不接受显式启用请求。
省略performance-output时默认保存至 `results/lan_continuous/performance/<独立ID>.json`。
报告不是完整轨迹，不能提高evidence_state或当成正式控制证据。

控制期不新增逐步打印、写盘、fsync或网络消息；固定性能缓冲（含预留）最多8MiB，
只保留全程汇总、近期256、最慢8及可选首N原始样本。退出和worker清退后集中保存，原子发布且不覆盖文件。
写盘失败会单独显示，控制终态保留；headless返回非零。观察器故障标记partial并停止后续采集，
不吞掉控制异常。观察与快照成本仍受原绝对截止保护，不宣称零开销；
单行observation_ns测到终端时间戳，后续固定直方图/打包/缓冲存储尾操作无法完全自测，报告声明此边界。

离线读取并校验报告，无需启动控制或P1/P2：

```python
from secure_control.experiments.live_timing import load_timing_report
report = load_timing_report("results/diagnostics/cart-pole-timing-01.json")
print(report["metrics"]["work_elapsed_ns"])
print(report["metrics"]["sample_interval_ns"])
print(report["control_outcome"], report["raw"]["complete"])
```

实测前记录A/B代码SHA、各自接入方式和配置；报告自动记录本机SHA/dirty及配置摘要，
对端SHA/接入方式未经核实记unknown。正常停止后保留报告、三方终端结果和运行设置，
不要用不同计时/记录/网络条件的两次数据声称净性能收益。阶段A只交付观察软件；
#132的瓶颈归因与优化仍待用户两机新数据（AC7–8未完成），不自动关闭Issue或追加性能运行。

### 原截止模式的已有摘要

先确认三个角色的最终JSON标识实际使用 `insecure_tcp`，Client还应为
`wire_profile=control-dynamic-matrix-v1`、`material_source=worker`。
控制方程、矩阵材料、双提交和原模型0.02s均保留；取消TLS只影响信道加密/身份认证。
两台电脑请用同一PR整合后的完整提交，旧PR125或只含矩阵核心的main不能替代此入口整合。

需要观察原截止模式时，重启B的P1/P2，再在A省略 `--non-realtime`：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-demo.example.yaml --headless-continuous --recording light --segment-steps 400
```

此时 `timing_mode=absolute`，周期从计划采样起点计算，包含仿真设备确认、记账及跨段维护。
任何超期沿原规则停止；不是把本次已批准演示改成40 ms控制。需要动画时只去掉
`--headless-continuous`，GUI与headless使用同一后端；窗口刷新率不能当作控制周期。

headless结束时输出一行JSON；Ctrl+C请求正常停止，先等最终JSON和双方停止回执，再重启三个角色。
如需保存原始摘要，可先创建本机临时输出目录并用PowerShell保存stdout（下例仍是截止模式）：

```powershell
New-Item -ItemType Directory -Force .tmp | Out-Null
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-demo.example.yaml --headless-continuous --recording light --segment-steps 400 | Tee-Object -FilePath .tmp/cart-pole-client.json
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

## 旧batch静态反馈与完整留证路线

本节使用原 `lab-client-cart-pole.example.yaml`（experiment为`cart_pole_lan.example.yaml`、wire省略或batch-v1），
配套通用 `lab-p1.example.yaml` / `lab-p2.example.yaml`。不得沿用上节matrix配置运行finite/full/预送。
本机已改过旧配置时，应先核对这三项；以下保存/回放描述不适用于上节light演示。

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
