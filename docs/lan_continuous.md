# 独立三角色连续 LAN 实验（Issues #86、#84、#75、#92）

## Issue #153（续接D132-20）：集中修复后的显式校准候选（新实采尚未运行）

按[集中修订](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6471238272)，
在同一PR151实施v5窄解析、File候选/目标过滤及公开流量校准入口；不再把调查文档当作补齐。
业务控制协议、20ms、GC、网卡/系统全局设置、D19维护优化及原Memory入口保持。

### 离线工具已准备，v5已完成独立交叉核验

选定Microsoft官方TraceEvent 3.1.21，工具仅在被忽略的`.tmp/d20-tools/`。
官方[GitHub发布](https://github.com/microsoft/perfview/releases/tag/v3.1.21)与
[NuGet包](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/3.1.21)
的TraceEvent DLL字节完全一致，SHA256：
`401e948dac99d0f9756ef96d5a8b8e4736e19e9f82ce8cdd744495951e3a94bb`。
Authenticode状态Valid，签名者Microsoft Corporation，证书指纹
`245D262748012A4FE6CE8BA6C951A4C4AFBC3E5D`。
使用现有PowerShell7.6.5/.NET10.0.11及包内FastSerialization读取离线文件；未安装服务、SDK
或Python依赖，未启用provider。包/解包/候选源码等总量低于64MiB，三份独立CSV输出合计
14,544,753字节，低于32MiB。完整摘要/引用和依赖审计在本轮实施评论及临时tool-manifest中。

发布tag对应公开源码commit`4b14fe0c8c6101cb3c1c6bfed2e317a9d29f68ee`。
DLL ProductVersion内嵌构建标识为`04132a81a0b2c147d48661d2b104f4ab7d136cd5`，
该标识在公开仓库查询为404；不能声称已复现完整DLL构建。已核对公开tag中的CSwitchTraceData
字段访问与签名DLL相关getter IL，并通过独立DLL实际输出核验适用的字段布局。
它替代上轮未验证的9f071a5候选，不从邻版本猜布局。

| 原ETL | v5条数 | 独立对齐字段 | 差异 | 每CPU切入/切出链不一致 |
|---|---:|---|---:|---:|
| 01 | 128095 | 原文件事件序号、QPC、CPU、28字节长度、新/旧TID、旧状态、version | 0 | 0 |
| 02 | 129239 | 同上 | 0 | 0 |
| 03 | 128645 | 同上 | 0 | 0 |

本机build26200/x64的385979条实际事件已逐条核对。`_cswitch_v5`仅接受已核验的
THREAD/id0/opcode36/version5、x64、28字节，保留v2/v3的TDH路径，未知长度/版本/架构拒绝。
新TID取payload中字段而非可能为0xffffffff的header TID，CPU取对应buffer context。
v5的schema_source指向公开tag，schema_sha256是固定布局契约说明的摘要，不是TDH数据或源码
文件摘要；独立DLL摘要在上文。旧v2/v3仍保留实际TDH schema摘要。
旧ETL缺失目标生命周期前缀仍不能归因；解析修复不补造历史start。

### TCP链路：实际enable证明和完整公开流锚点，不猜来源

File候选显式设置`NonPagedMemory="true"`。WPR默认false会使用分页缓冲；
[微软日志模式文档](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
说明内核provider不能写入`EVENT_TRACE_USE_PAGED_MEMORY`会话；
[微软WSL的同GUID配置](https://github.com/microsoft/WSL/blob/afa988cfb498fb9794718683823fb38dbc96673d/diagnostics/wsl.wprp)
也显式使用非分页内存。候选据此修正，未更换provider/事件/关键词或启用系统全局设置。
实际QueryAllTraces的LogFileMode在开始及结束均核对，分页或模式缺失不放行。
旧运行未保存该会话字段，不能仅凭修正宣称已唯一解释旧TCP0，更不能声称新实采已通过。

只读prepare与启动前各记录带UTC/QPC时间的已启用实例快照；它们不证明自有会话启用。
启动后仍独立核对自有logger与实际注册实例。File来源审计版本升为2，计划明确
`native_nonpaged_buffer_bytes=12582912`：总缓冲仍12MiB，非分页分配从原系统8MiB增至12MiB。
旧计划/旧批准不能复用；Memory历史入口保持。实际TCP产出及流/序号关联仍待新批准校准。

新File入口在自有两个session创建后，以QueryAllTraces的session ID/GUID与
EnumerateTraceGuidsEx返回的TRACE_ENABLE_INFO对应，核对本次TCPIP enable、level5、
MatchAny/MatchAll及实例flags。PRE_ENABLE(0x2)仅表示provider注册前预启用，不能证明
实际来源存在；必须有不带该标志的匹配注册实例，允许其与预启用记录共存，不以PID0拒绝。
失败不启动Client子进程/公开流量，保存失败事实并收尾。
TDH注册清单或profiledetails不再代替本次实际enable证据；event-ID过滤仍由固定profile绑定，
运行时enable查询本身不返回ID filter，实际ETL descriptor统计继续验证。

新旧provider都为`2f07e2ee-15db-40f1-90ef-9d7ba282188a`；未扩大provider、keyword或payload。
旧TCP0可排除“只是Python解码器不认识已有所选descriptor”的单一解释：全descriptor遍历和
系统tracerpt摘要均无该GUID。不能由此认定未启用、没有网络或仅由Memory覆盖造成。

| ID | 已核实版本 | opcode/事件level | keyword | 解码的元数据 |
|---|---|---|---|---|
| 1033 | 0/1 | 0/4 | 0x8000000400000484 | Tcb/LocalAddress/RemoteAddress/ProcessId，v1含ProcessStartKey |
| 1038 | 0/1 | 0/4 | 0x8000001000000404 | 同上 |
| 1040 | 0/1 | 0/4 | 0x8000001000000484 | 同上 |
| 1043 | 0/1/2 | 0/4 | 0x8000001000000484 | 同上（版本>0含ProcessStartKey） |
| 1074 | 0/1 | 0/4 | 0x8000000200000000 | Tcb/NumBytes/SeqNo，v1含NumPkt |
| 1300 | 0/1/2/3 | 0/4 | 0x8000000400000484 | Tcb/LocalAddress/RemoteAddress/Pid，版本>0含ProcessStartKey |

选择器仍为level5、MatchAny`0x600000484`、MatchAll0和上述六ID；注册模板的其他字段继续由
原白名单审计，不导出业务payload。新增已存在的1043v2/1300v2-v3解码只走实际TDH字段核查。
微软[1074说明](https://devblogs.microsoft.com/scripting/use-powershell-to-parse-network-log/)将其
描述为received data/ThSeq；这里仍只称选定组件的数据覆盖，绝不称物理包到达或socket readable。

一次校准检验的具体假设是：原窄来源实际启用后，File保留窗口中的两条新建公开连接能产生
可按PID/TCB/四元组/方向/生命周期关联的1074记录。公开流包含全部setup及维护形状帧，长度变化，
检验SeqNo起点语义，处理回绕/重传，缺流、前缀、方向或连接复用保持unknown。若仍为0，结合
本次enable及完整窗口证据判定源工作条件/选择仍不足；不追加其他provider或自动重跑。

### File与离线处理已实施的固定候选预算

独立profile为`configs/control-tail-calibration.wprp!D20`，File顺序日志，显式`-filemode`。
系统/事件缓冲8MiB/4MiB不变；有效native窗口最多55秒，公开应用窗口至少40秒，收尾目标10秒、
专项总目标100秒。最终ETL目标128MiB、目录/临时目标384MiB、启动余量2GiB；WPR及异常系统调用
不提供硬配额/退出保证，停止或GUID归属无法确认仍人工处理，不能停止别人会话或自动重试。

`read_calibration_etl`是独立预算入口，旧read_etl的64MiB/30万限制保持。校准输入最多128MiB，
解码预算250万事件；耗尽后在下一个ETW缓冲边界取消离线处理并标partial，不冒充完整遍历。
计数包含过滤前descriptor/错误/丢失；保留最多10万条目标线程/进程和其TCP元数据，其他行不保存。
窗口外、已明确结束且未复用TID的terminal switch-out单独保存边界证据，不冒充窗口内缺口；
窗口内/无归属/复用仍拒绝。
校准报告分别保存`lifetime_replay`与`window_replay`。窗口验证保留全文件丢失/解码/容量、
生命周期及CPU链门禁，只允许唯一生命周期中窗前明确切入作为Running锚点；目标CPU驻留
必须连续且唯一。锚点至窗末的未知状态、Ready冲突或切换缺口仍拒绝；窗内较晚锚点不能
跳过窗口开头。全生命周期的前缀异常及原事件CPU/index/旧状态仍保留供审计，通用重放规则不变。
同时核查目标生命周期夹住窗口、内部切换/唤醒序列和全局每CPU切换链；缺前缀、内部缺口、
unsupported或保留耗尽都不能设完整。输出JSON合计32MiB、实际进程峰值工作集目标512MiB并核对。
输出/峰值/ETL超限判失败，不用仅增大数字掩盖原全量行内存问题。

容量推导仍是估计：原三组文件约9.8–10.1MB，保留调度包络5.7–13.2秒，总事件/包络的最坏
容量代理约37k/s，55秒约204万事件/98MB。代理不是稳定发生率，加入TCP和机器负载变化后
可能超预算。File写盘扰动组不能直接与旧Memory计算因果提速。

### 可执行的显式入口与唯一下一批准动作

校准不运行plant或控制协议：B单进程两个端口回显，A由native开始后spawn的独立主线程在
约41秒内双向发送公开确定性变长帧。B等待连接最多45秒，连接齐后独立计业务55秒，
合计最多100秒；A原生采集上限仍55秒。两端均最多一次，首错停；只接受明确两机字面量地址。
入口要求新的`native-calibration-authorization-v1`文件，绑定准确源码SHA、完整计划摘要、ID、
两端新输出绝对路径、attempts严格整数1/窗口55，以及本次用户批准评论URL；设计评论和旧额度
不能冒充新运行批准。源码/候选profile脏时拒绝，用户部署及工作流修改保留。计划绑定拓扑摘要。
下面命令中的SHA必须对应同一已审版本，批准文件仅在用户批准后生成；当前未生成有效批准文件。

```powershell
# A：只读准备，--config选用已核实的A端部署文件；不启动采集/控制/流量。
$runHead = (git rev-parse HEAD).Trim()
uv run python scripts/run_control_tail_diagnostic.py prepare-file-calibration .tmp/d20-plan.json --expected-head $runHead --config configs/lab-client-cart-pole-demo.example.yaml

# 获批且两端同SHA后，将同一plan/批准文件复制到B，先执行B，再立即执行A。
uv run python scripts/run_control_tail_diagnostic.py calibrate-pair results/tail_diagnostics/d20-calibration-B --expected-head $runHead --plan .tmp/d20-plan.json --authorization .tmp/d20-authorization.json --p1-config configs/lab-p1-cart-pole-demo.example.yaml --p2-config configs/lab-p2-cart-pole-demo.example.yaml
uv run python scripts/run_control_tail_diagnostic.py calibrate-client results/tail_diagnostics/d20-calibration-A --expected-head $runHead --plan .tmp/d20-plan.json --authorization .tmp/d20-authorization.json --config configs/lab-client-cart-pole-demo.example.yaml

# 停止后把完整B目录原件复制到A，再只读核对两端同ID/SHA/拓扑/计划、帧数及原件hash。
uv run python scripts/run_control_tail_diagnostic.py calibrate-analyze results/tail_diagnostics/d20-calibration-A results/tail_diagnostics/d20-calibration-B --output .tmp/d20-calibration-result.json
```

各输出目录/结果文件必须全新，ledger先于监听/采集；已有目录拒绝复用。A本地检查通过也只标
local_checks_complete，双机校准结果必须再核对B原件。源query/启动失败、窗口不完整、流未知、
超资源、两端身份或摘要不匹配都不通过；ETL和失败前缀保留，不补跑。

**唯一下一批准动作**：软件独审后，批准该固定SHA和原窄来源/上述预算的一次公开两机校准，
并确认两端设备/配置可用。此批准不包含正式2000步控制实验。当前新实采、新流量、实际窗口
覆盖、TCP产出及资源峰值均NOT RUN；软件/离线v5通过不能替代它们。校准任一FAIL/PARTIAL
就报告具体阻断并停止，三项实际能力通过后才申请正式根因实验。

## #153：原控制慢步诊断入口（新控制运行尚未授权）

目标为逐个解释`work > 20_000_000 ns`的步骤及前后最近正常步，不以公开回显校准全绿或
提速对比作为交付。原117步缺少的TCP事件不能事后补回；新运行只能解释新复现。

`prepare-control-file`只读生成purpose=`control-slow-step-v1`的File计划，绑定三角色公开
配置语义、拓扑、审查链接和源码。`client/pair --authorization`只接受新的
`native-control-authorization-v1`记录，绑定同计划摘要、diagnostic_id、两端新绝对路径、
严格整数attempts=1/steps=2000。v3回显及旧#132许可不能复用；批准无效在ledger/采集前拒绝，
一旦尝试即由原单次ledger永久扣减，失败不退额、不重试。

A沿原Client+worker/stream-map入口，原owner在spawn前启动File会话、子进程退出后收尾；
55秒原生上限、12MiB非分页缓冲、128MiB ETL/384MiB临时目标、2GiB余量保持。B使用已有
首request_receive观察点记录一次业务起点：等待至多45秒、业务至多55秒、总至多100秒。
原20ms模型周期、协议/矩阵、GC和网卡设置保持；超时保留partial，不缩短2000步冒充成功。

停止后唯一有界读取目标Client PID/TID/实际工作首末；保存带摘要的原生视图与目标元数据。
离线峰值512MiB/JSON合计32MiB仍是软目标，超限失败而不重跑。没有新控制运行批准文件。

下面是审查后、获批且两端固定同一SHA时的执行形式。`$runHead`和`$reviewUrl`须对应最终已审
版本；准备生成的计划及获批后生成的批准文件须原样复制到B，输出路径必须与批准一致。
本节命令不是现在启动控制采集的授权。

```powershell
# A只读准备
uv run python scripts/run_control_tail_diagnostic.py prepare-control-file .tmp/d153-control-plan.json --expected-head $runHead --software-review $reviewUrl
# B先启动
uv run python scripts/run_control_tail_diagnostic.py pair results/tail_diagnostics/d153-control-B --diagnostic-id d153-control-once --expected-head $runHead --software-review $reviewUrl --window 2000 --steps 2000 --native-plan .tmp/d153-control-plan.json --authorization .tmp/d153-control-authorization.json
# A紧接着启动（管理员）
uv run python scripts/run_control_tail_diagnostic.py client results/tail_diagnostics/d153-control-A --diagnostic-id d153-control-once --expected-head $runHead --software-review $reviewUrl --window 2000 --steps 2000 --stream-map --native-plan .tmp/d153-control-plan.json --authorization .tmp/d153-control-authorization.json
# 将B完整目录复制到A后，只读逐步分析
uv run python scripts/run_control_tail_diagnostic.py analyze-control results/tail_diagnostics/d153-control-A/manifest.json results/tail_diagnostics/d153-control-B/manifest.json --output results/tail_diagnostics/d153-control-analysis.json
```

逐步表含run/step/round、work/exchange、A发送/首次读/收齐、线程Ready/Running区间、B本地
处理span、原件摘要、时钟域和缺证据原因。只同机相减；Running不是Python/GIL可用证明，
等待不是网络延迟证明。控制连接以现有已校验lan_setup回复后的静止边界证明本次独立SeqNo零点：每连接一次记录
累计接收N/checkpoint及下一已有send进入时刻。B在该回复后仅等待offline请求，无主动推送。
原socket从任何应用握手前注册；并发/PEEK/旁路IO使证据失效。完整新连接1033出生事件、
PID/四元组/TCB唯一关联后，checkpoint前序号区间并集必须唯一连续且恰为N，直至下一send
不增长；缺首部、空洞、未来补洞、TCB复用或时间相等歧义均返回具体unknown。先有界保留
TCP元数据再关联，避免回调绑定晚于数据而丢失前缀。锚点及每帧首次覆盖证据均绑定原件摘要
和事件索引，不复用v3序号、不把首个普通控制帧当0。业务窗外额外+1单独保留unknown，
不猜FIN；若影响目标区间/生命周期则该帧拒绝。通过时给出A等待在组件覆盖之前/之后的
同机时间分段；该组件仍不等同socket可读，不能承诺一次拆开B读取前和网络等待。若无慢步返回not_reproduced；不完整包无慢步另标incomplete，均不补跑。

### #159：已有原件的独立重分析

`analyze-control`可直接读取原有hash绑定的events/view/stream，不重新读取ETL或启动采集。
只用1033连接完成之后、setup checkpoint之前的完整序号并集独立确定应用零点；并集
必须恰好等于应用累计N。连接完成前的观测必须完全被这个独立前缀覆盖、处于同一进程
生命周期且无连接身份冲突，否则仍unknown。通过时把其索引、时刻、长度和post覆盖见证
保存在`pre_connect_observations`；这些观测不进入业务packets或提前complete_at，也不猜测
其为SYN/FIN。连接完成同刻的数据保守拒绝，不能靠时间容差放行。

新增`cpu_residence`与每步`cpu_residence_intervals`：在原全文件质量、CPU链、唯一生命周期
和目标跨CPU唯一驻留门禁通过后，只以实际CSwitch边界证明半开Running/Not-running区间。
窗口必须由实际切换边界夹住，不用线程结束或窗口长度补齐缺边界。Ready事件与切出状态
2/3/7不会改变这一驻留结果；原严格Ready重放及失败状态保持。状态名见
[Microsoft CSwitch定义](https://learn.microsoft.com/en-us/windows/win32/etw/cswitch)。
同一原始事件的旧/新TID相同时，仅在当前已驻留同CPU、out/in同刻配对时作为连续驻留，
保留事件索引，不生成离CPU间隙；错CPU或无匹配驻留仍拒绝。
Not-running不等于Ready或网络等待，Running也不证明Python/GIL可用或有效计算时间。

每方`A_wait_analysis`新增`residency_verified`、`running_residency_ns`、`not_running_ns`、
`unknown_ns`；缺证据时前两项计时为null、未知时长保留，不能记零。旧Ready字段仍只在
严格重放成功时可用。`capture_source_head`与`analysis_source`分别记录采集SHA、分析SHA、
分析模块摘要和脏状态；原manifest的`diagnostic_complete`及旧`schedule_window_complete`
不会改写。输出使用新文件名，保留旧分析结果，不因解析改善而自动宣称根因已查明。

### #161：已有A ETL的显式离线恢复

仅对原A视图唯一失败为`event budget exceeded`的既有控制结果启用；不启动WPR或控制。
`recover-control <A/manifest.json> <新恢复目录> --expected-head <分析SHA>`使用独立Python进程，
显式预算为5,000,000个全文件callback、120秒watchdog、100,000保留行、128MiB输入ETL、
512MiB进程峰值工作集目标及32MiB派生输出。旧读取入口的2,500,000上限不变。
超时仅结束此离线进程；不自动重试、拆片绕过累计预算或提高阈值。输出目录必须全新。
逐事件审计所有描述符、关键错误和CPU切换链，筛选仅控制保留量；正常EOF与所有质量检查
通过才有`scan_complete`。线程状态、CPU驻留、TCP锚点和逐帧覆盖仍各自验证。
`request.json`、`receipt.json`记录原manifest/ETL/sidecar摘要、采集/分析SHA、策略及资源；
原件读前读后摘要须一致。新view/events独立保存，旧manifest/view与失败状态不会改写。
使用`analyze-control <A/manifest.json> <B/manifest.json> --a-recovery <恢复目录/receipt.json>
--output <新分析.json>`显式消费恢复证据；拒绝跨run/变更输入/摘要或目标不符。
恢复可验证本次A组件覆盖至读取的等待，不能仅靠两个主机时钟求两个方向单向网络延迟。

### #161：B组件到首读的单次验证准备

新用途`control-b-receive-boundary-v1`只验证B端请求组件覆盖至首次成功recv/帧收齐的等待。
不实现PktMon/NIC边界，也不能把组件前等待称为纯链路时延。普通入口默认关闭。
B在accept后、任何hello字节读取前，只包装Client连接；peer连接不包装。固定8192帧、
655360字节数字缓冲计入原每角色6MiB限额；所有setup/维护字节计数，只有请求身份校验
通过才绑定step/sequence。失败/EOF、PEEK、旁路或并发使观察不完整，不改变原业务异常。
首字节组件覆盖与整帧覆盖分别报告；首读早于整帧覆盖时后者到首读为null，不填零。

B独立setup锚点记录已校验setup请求累计N及回复send进入时刻。A原同步请求等待这份回复
才发下一请求，故此段是既有协议的静止边界，不增加网络消息。1017接受连接完成事件和
1074连续前缀证明本次接收序号；1017必须有成功Status=0，缺失或失败不建立锚点。
1034失败和1300存在事件不能代替出生证据。
B单个自有File会话在P1/P2创建前实际启用，停止后一次解码保留两个目标的ProcessThread
生命周期和TCP元数据；不新增CSwitch/Ready/DPC/堆栈采集。

预算候选需新批准：A保持12MiB非分页缓冲/native55秒业务上限和100秒原生收尾目标；
B为6MiB（ProcessThread2+TCP4）、监听等待45秒、业务55秒、原生及本端总墙钟目标120秒。
B活动/清理截至原生开始后110秒，stop最多10秒且不超120秒剩余预算；首业务开始后将
业务截止收紧至55秒。等待45秒含本端准备开销，不承诺任意晚启动仍运行2000步，超时
保留partial。两端各ETL128MiB、临时384MiB软目标、磁盘余量2GiB、离线峰值512MiB和
JSON合计32MiB软目标保持。B6MiB/120秒是本阶段显式新增预算，不能套用旧批准。

两机均使用管理员PowerShell。下面命令只读准备；`$runHead`及`$reviewUrl`必须对应本阶段
最终已审版本。当前软件实现不授权真实采集。

```powershell
# A：准备本机原生节点
uv run python scripts/run_control_tail_diagnostic.py prepare-control-file .tmp/d161-A-node.json --expected-head $runHead --software-review $reviewUrl
# B：准备本机接收节点，实际TDH版本可与A不同
uv run python scripts/run_control_tail_diagnostic.py prepare-b-receive-file .tmp/d161-B-node.json --expected-head $runHead --software-review $reviewUrl
# 将B节点原样复制到A的.tmp后，在A组合不可变root
uv run python scripts/run_control_tail_diagnostic.py combine-b-receive-plans .tmp/d161-A-node.json .tmp/d161-B-node.json .tmp/d161-root-plan.json --diagnostic-id d161-b-receive-once-01
```

root绑定两节点完整内容和摘要、各自准备机器/角色/公开配置/拓扑、相同源码SHA、review及
run-id。新的`b-receive-authorization-v1`批准记录包含purpose、source_head、root的
`plan_sha256`、diagnostic_id、严格整数attempts=1/steps=2000、两端新绝对输出路径和新
`https://github.com/GNYKCZ/secure_pid_hvac/issues/161#issuecomment-...`授权记录。
旧153授权不可复用。root与批准文件须原样复制到B；只读准备可做，运行前须另有具体批准。

```powershell
# 获批后B先启动，A紧接启动；两端root及authorization完全相同
uv run python scripts/run_control_tail_diagnostic.py pair results/tail_diagnostics/d161-B --diagnostic-id d161-b-receive-once-01 --expected-head $runHead --software-review $reviewUrl --window 2000 --steps 2000 --native-plan .tmp/d161-root-plan.json --authorization .tmp/d161-authorization.json
uv run python scripts/run_control_tail_diagnostic.py client results/tail_diagnostics/d161-A --diagnostic-id d161-b-receive-once-01 --expected-head $runHead --software-review $reviewUrl --window 2000 --steps 2000 --stream-map --native-plan .tmp/d161-root-plan.json --authorization .tmp/d161-authorization.json
# B完整结果目录复制到A后，只读分析新慢步及邻步
uv run python scripts/run_control_tail_diagnostic.py analyze-control results/tail_diagnostics/d161-A/manifest.json results/tail_diagnostics/d161-B/manifest.json --output results/tail_diagnostics/d161-analysis.json
```

B新增`P1.receive.json`、`P2.receive.json`、`native-b.etl`、`request-native-events.json`及
`request-native-view.json`由manifest的`b_request_evidence`摘要绑定。分析逐方新增
`B_receive_analysis`：独立匹配A发送累计区间与B已验证请求区间后，只在B本地域计算
首字节组件→首读、整帧组件→收齐及recv进入位置，保留索引、原件hash和具体unknown。
这能判别B组件至应用读取是否贡献长尾，不能区分栈交付/调度/GIL，更不直接跨机减QPC。
无慢步如实报告未复现，失败不退额度、不换ID或目录补跑；不取消其他用户会话。

## 维护候选与采集有效性（D132-19，软件阶段）

按[D19设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6464649290)，
本轮以 `f4f078ed4f7ce84ddbab5ce7fb9f7c237dce70fc` 为基准，分别验收以下两项。
这是人工有限软件续接累计7/7；只有一次独审，新Finding先报用户，不自动返工或实测。
当前角色映射采用用户最新配置 design5/work7/review5，替代设计评论里的旧对话名称。

### A：同一次复合维护的两路就绪处理

只有显式 `client_io: ready-v1` 的原compact continue路径复用 `_exchange_two_frames`。
两份完整请求仍先编码核查，再发送；每方回执一到即验证身份、计数、段链和epoch，
独立推进该方序号。P2先确认后P1失败时保留P2事实，终止不确定会话，不重试。
成功记录仍按P1/P2排序；双方确认、源核查、release与原截止检查后才激活下一段。
服务器仍在回复之前准备下一prefix，消息数/wire/数学/材料/GC/20ms周期均不变。
stop/switch、旧模式和TLS继续使用原收发路径。维护不伪装为普通控制帧写入流映射。

原三组每组2000步、每400步维护，12次continue的公开计时如下（毫秒）：

| 已测区间 | 最小 | 中位 | 最大 | 可得结论 |
|---|---:|---:|---:|---|
| 全维护 | 8.2293 | 9.6464 | 10.5347 | 原维护真实开销，不能全部算作可消除收益 |
| maintenance_advance | 7.8327 | 9.2599 | 10.1450 | 包含请求准备、网络等待、服务器准备及回执处理，不能叫纯网络 |
| maintenance_source | 0.3353 | 0.3584 | 0.3745 | 源检查占较小部分，继续保留 |

来源为三个原A目录的 `manifest.json/control_samples/phase_durations_ns`；步号399/799/1199/1599。
这些区间没有进一步隔离服务器prefix准备和等待，不能从历史数据证明串行接收就是根因。
软件oracle只验证消息和状态等价。新实机改善值 **NOT RUN**；117个exchange慢步仍未解释，
本候选也不构成它们的修复结论。

### B：采集选择核验与明确阻断

`prepare-native`现在同时保存实际TDH descriptor的provider、version、level、keyword，
检查每个版本与固定provider、level5、原keyword `0x600000484`、原六个event-ID筛选相容。
`source_selection_audit_version: 1`区分这项来源核验；旧字段列表计划不足以通过新preflight，
需要重新做只读准备，不能改写旧计划或旧ETL。实际源列表在启动前仍重查，不放宽字段白名单。
没有更换keyword、扩大provider、增加缓冲或改Memory模式，也没有新增生产协议/报告schema。

本机只读核查（WPR 10.0.26100）确认profiledetails中的128×64KiB系统缓冲、64×64KiB
事件缓冲、六个ID/level5/keyword均与profile一致；TDH的15个已注册事件版本均满足选择条件。
这是配置/注册信息的证据，**不是旧会话运行时已经正确启用或实际产出事件的证明**。

| 必要证据 | 原三组结果 | 本轮结论 |
|---|---|---|
| TCP事件且目标流/SeqNo锚点可信 | 三组TCPIP均0 | FAIL；缺失原因尚不能确定，不能猜mask后重采 |
| 调度覆盖应用首末窗口 | 应用40.7005/40.7374/40.5888秒，保留调度包络仅10.4158/5.6851/13.1604秒 | FAIL；包络也不证明内部无缺口 |
| 目标线程生命周期 | 三组目标main-thread start均0 | FAIL；native先启动再spawn Client，仍未保留完整前缀 |
| 实际CSwitch版本可解释 | v5事件128095/129239/128645；本机TDH1168 | BLOCKED；不套v3布局 |
| QPC/loss与资源记录 | QPC且lost0；旧资源例外保留 | 必要但不足，不升级为完整采集 |
| 本轮新事件验证 | 未运行新的两机控制实验或系统采集 | NOT RUN；不能称ready-to-run |

[WPR官方Logging Mode说明](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/logging-mode)
规定Memory使用环形缓冲，旧事件会被覆盖；lost0不能证明首窗口仍在。
它与当前只保留尾段的现象相容，但不能单独解释所有TCP事件缺失。
[ETW选择规则](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)
也只说明level/keyword筛选的必要条件，不保证指定工作负载一定触发事件。

### 下一次联合验证的前置条件（尚未授权运行）

先为实际CSwitch v5取得可靠字段来源，并核实原生会话实际启用链及TCP目标流锚点。
覆盖方案有两条待决路线：保留12MiB预算但缩短观察窗口（不再是原2000步实验），或经用户
批准采用File/更大缓冲覆盖约40秒。前者更容易保留前缀但可能不复现尖峰；后者引入写盘扰动
或额外内存，必须先明确数值上限、停止/保存策略及可接受例外。现有256MiB临时磁盘目标、
64MiB最终ETL与12MiB原生缓冲不是新扩容许可；File模式本身不提供硬文件上限。
仅改存储模式也不能解决TCP为0或v5无法解码的问题。

上述前置软件与独审完成后，另提一组同head两机2000步/约40秒的具体预算和启动命令，
经批准才能执行。该组可分别判断维护实际耗时与采集覆盖是否有效；若诊断扰动和历史组不同，
不得直接算百分比提速或声称因果改善。缺前置条件就停止，不能以本机替代、试采或连续重跑。

## 绝对节拍与演示计时（D132-14）

动态持续light入口省略`--non-realtime`时，复用既有`AbsoluteCycleClock`：
目标为`t0+kT`，跨段不重设t0；输入、通信、施力、记录及维护共用原周期截止。
恰到截止也按超期处理。此模式在超期时依原契约停止，不保证Windows准时唤醒。
显式`--non-realtime`为非实时演示，以前次实际采样加T等待，无周期截止；
模型T均保持原场景20ms，演示模式的采样间隔偏差可能累计，不能说成算术耗时。
本次没有改变默认模式、时钟、等待算法、控制或通信协议。

```powershell
# 已按两机部署说明启动P1/P2后，在Client运行动态持续light绝对节拍：
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-demo.example.yaml --headless-continuous --recording light --performance samples
# 演示模式是在同一命令上显式添加 --non-realtime；sample-limit仅保存容量，不限控制步数。
```

GUI沿原100ms快照刷新，显示采样迟到、采样至施力、完整工作及周期余量/超期。
迟到=`max(0,actual_sample_start-scheduled_start)`；余量/超期分别是
`max(0,deadline-work_completed)`、`max(0,work_completed-deadline)`。
均用Client既有同域整数端点，不相减不同电脑时钟。
完整工作仍含维护与已有观察成本，固定末尾统计/写缓冲自身未自计时，但仍受原严格截止复查。
未完成工作不填失败出口时间，显示“未完成”；演示无计划显示“不适用”，不伪造0。
余量为0且超期为0表示“已到截止，不算准时”。实际相邻采样间隔可一长一短，
不能仅凭间隔>20ms判周期失败，也不能凭均值接近20ms保证零迟到。

新保存性能报告`cart_pole_live_timing`的`format_version=2`，新增迟到/余量/超期固定汇总
（计数、总和、极值、missing_count，无额外直方图），行值从原端点派生。
新reader严格校验v2；v1保持旧字段/算式并可原样读取，包括缺single_exchange的历史例外，
不会自动重写旧文件，未知版本拒绝。旧reader不承诺读取v2，分析工具需升级；
三端控制线格式没有变化。缓冲仍≤8MiB，完整样本≤10000、近期256、最慢8，退出后集中保存。
`correct_last`会撤销此前临时成功的新增统计，观察失败标partial，不掩盖真实控制状态。

这里只完成软件计时与模式说明，没有新增控制性能运行或双机/长期20ms资格证据。
D13已有结果继续标记Work实测、未独立结果复核。

## 公开计划临时对象生命周期（D132-13）

服务器恢复/绑定会校验公开计划并建立独立peer快照。递归校验与复制使用模块私有helper，
复制memo仅属于当前调用，避免每轮局部递归闭包的自引用环滞留公开图至循环GC。
仍逐轮新建独立计划/快照，保留图别名、原摘要与非标准表示的deepcopy语义；
不缓存逐轮身份、不复用随机材料/生命周期，也不改变正常GC或控制时序。

软件引用图检查能验证不再产生这两类临时闭包环，但不证明它们解释全部gen2扫描成本。
本阶段没有新增性能运行；长期最慢耗时及双机收益需另行验证，不能据此宣布GC尖峰已解决。

## 显式2000步诊断窗口与原生采集准备（D132-17）

依据[2000步设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6460925858)，
`client`、`pair`诊断入口增加显式`--window 2000 --steps 2000`窗口声明。
按[D17R用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6462410802)，
取消先前两项资源硬保证导致的无条件封锁；仅放行其余检查完整的显式2000路径，
没有force/ignore开关。100秒为停止监督目标，OS异常下不保证ETW已经结束；
含临时256MiB为磁盘目标而非硬配额，WPR merge峰值可能超过。
两项固定例外及批准来源进入准备计划、两端plan、manifest和原生报告；其余限制不变。
旧默认窗口、`local`入口和旧v1文件的400步边界不变；这不会改变日常动画配置或控制算法。
业务段仍为400步、材料库存16，控制身份0…1999，材料身份0…2015；
399/799/1199/1599后继续下一段，1999结束，不发第2001次控制。
此项用于定位延迟，不是提速，也不表示20ms实时资格通过。

容量、schema、计时预算统一由`execution.diagnostic_limits`声明。
新文件显式使用`control-tail-diagnostic-v2`及`client-stream-map-v2`并包含完整`limits`；
旧v1精确读取，未知schema、版本混配、声明不一致均拒绝，不重写旧结果。
2000窗口每角色普通事件最多61440、GC事件10240、身份槽2016；
Client流映射最多4000条、320KiB。每角色诊断数值缓冲≤6MiB、四角色≤24MiB；
当前四份角色缓冲加Client流映射精确为19726080B。
这不是业务RSS、Python导出对象或原有light计时内存的上限。
溢出保留partial，不能扩大容量或只保存末400步掩盖丢失。

一次新`two_host_2000`账本在启动前扣为0；失败也不恢复、不换目录补跑。
Client活动上限90秒，两端各总监督240秒。A原生目标窗口100秒包含10秒停止预留；
监督器至90秒停止业务采集，进程清退也受这一边界约束。
只启动本端成员，只清理自有PID树，不远程控制B，不改GC、网卡或系统优先级。

新增`prepare-native`仅查询本机TCPIP TDH字段、已有会话并调用WPR `-profiledetails`，
保存准备计划；不启用provider、不运行控制。A的2000窗口必须同时显式启用
`--stream-map`及提供同head准备计划`--native-plan`，B不启动原生采集。
A必须使用管理员PowerShell。正式启动前、账本扣减之前重新核验权限、仓库白名单profile、
原字节hash及实际TDH字段、工具、空间、会话冲突、新目录和同head；begin前再核验一次。
旧准备文件缺少本次例外声明会被拒绝，应重新prepare，不能手工改成自称已实测。
`configs/control-tail-native-2000.wprp`采用内存模式：ProcessThread/CSwitch/ReadyThread
64KiB×128，TCPIP 64KiB×64，总数值缓冲12MiB；不采stack或业务payload。
TCPIP事件ID严格为1033/1038/1040/1043/1074/1300，逐本机注册版本审计字段名、类型和flags。
宽keyword本身可能包含数据事件，因此不能删除ID过滤或遇到不支持版本后扩大provider。
离线reader还接受1038/1040/1043的已支持v0/v1；其他版本保留unsupported。

只有用户明确执行带计划的A诊断命令才调用WPR启动；使用本次随机唯一instance，
已有WPR/NT Kernel Logger不再仅按名称阻止准备，也不取消其他会话。
准备计划的`session_coexistence.version=1`绑定既有会话身份及稳定配置；
原始查询保留，完全相同的重复行去重，同名或同logger ID的歧义仍拒绝。
动态缓冲数、写入及丢失计数只作背景观测，不作为身份，也不混入自有QPC/loss门禁。
扣额前及紧邻start重新检查，背景稳定配置变化需重新只读prepare并重绑计划。
WPR使用独立`-instancename`；系统会话实际名称为
`WPR_initiated_<instance>_WPR System Collector`，事件会话使用profile的EventCollector名称。
启动后必须证明两个精确名称、全新logger ID、自有配置合格且背景会话未变化，才允许业务进程启动。
结束前后保留快照核验背景身份及配置；背景漂移使共存证明不完整，不能归因本工具。
失败只清理已证明属于本次独立实例的部分会话；查询失败、归属或ID复用不明时不盲cancel。
没有额外共存试采；实际WPR启动失败仍消费一次额度，不自动重试。
已有后台记录的内存、磁盘及负载另列，不能声称机器总开销只有本次预算。
此策略变更需要两端重新prepare、新SHA审查及root摘要绑定，不能继续使用旧计划。
启动后只接受两份同instance会话、QPC时钟和实际缓冲≤12MiB；
结束前核对GUID归属、loss、耗时与文件大小。单ETL≤64MiB、输出目录目标≤256MiB、
启动前空闲≥1GiB。内存模式避免持续ETL写入，但WPR停止合并时的临时总磁盘占用
仍未获得实际验证，不能将结束后的文件检查说成完整的256MiB硬配额。
目录检查包含子目录和非ETL文件；可观察超目标记录`resource_budget_exceeded=true`及partial，
停止后续自动处理，不删除原件凑预算，不改输出盘或系统配额。外部临时峰值明确未测。

原生操作系统调用或WPR失败不能被Python时限变成绝对保证：
启动超时撤销本次唯一instance的部分启动；已有GUID变化、无法复核归属、
停止超时或超过窗口时明确输出`*_manual_attention`，不宣称成功退出、不自动重试或停止别人。
这些故障意味着采集不完整，用户需要检查报告中的instance。WPR命令返回后仍查询本次
会话是否消失；命令超时/退出本身不作为ETW已经停止的证据。
provider启动前保存`native-owner.json`，成功启动后更新session GUID，结束后更新最终报告。
异常时在A管理员终端读取该文件的`instance`、`sessions`及`manual_recovery`，
先执行该instance的`wpr -status -instancename`检查，再对比会话名/GUID；只有确认仍为
本次自己的会话才使用文件内`save`命令，输出到新的`native-a-manual.etl`，不覆盖原ETL。
若GUID变更或无法核实归属则停止人工操作并反馈，不能全局stop/cancel或改用其他instance。
正常结束无需手动停止；手动保存不是再跑控制组，也不恢复已扣账本。
真实会话命名、退出、临时磁盘峰值、实际ETL descriptor/QPC/loss、SeqNo语义和流锚点
仍须在获准的唯一组中核验；软件mock通过不等于现场已验证。
本次软件复审通过且其他前置核实后，才交付精确的新ID/目录与两端命令，由用户启动唯一组。
代理不代跑/远程操作、试采或用本机替代，缺其他条件仍停止，不用例外绕过。

离线分析保留原样本、所有超20ms步骤、最慢8步与邻步，按五个400步段列出摘要。
`expected_maintenance_steps`是计划边界，`observed_maintenance_steps`来自实际maintenance计时，
不把计划索引当执行证据。普通、继续维护、末步停止及计时未知组分别统计，未知不填零。
`final_stop`仅表示成功停止前的末次已完成工作样本，不是停止握手自身的耗时。
必须同时有Client成功停止状态、完整主线程配对stop事件、停止前末次工作的时间/身份
及confirmed样本；预定最大步或最后观察步都不能单独证明停止。失败时清理补出的stop
也不能冒充成功停止；缺证据按已知普通/维护或未知分类，保留原样本与全分母。
两机必须采用同一新会话和版本，不能拼接旧B；跨A/B绝对时钟不相减。
TCP事件覆盖不等于socket可读，调度Ready不等于正在运行，不由本功能断言历史34ms根因。

发布两端最终实测命令前须完成当前head的软件独审及采集前置核实。
本轮为人工限定续接累计5/5（不重置），只允许本次实施/检查和原Review一次复审；
新的有效Finding需报告用户/Design，
不得自行继续返工、实测、补跑、合并PR或关闭Issue。

## 默认关闭的帧边界与Windows离线关联（D132-16B）

本功能仅是软件前置，依据[16B设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6446474476)。
普通GUI/headless与原轻量计时均不分配新流缓冲，不查socket地址，不启动ETW/WPR/PktMon。
只有未来获批专项中，A端诊断命令显式增加`--stream-map`才开启公开帧区间记录；
该参数本身不授权新控制运行，D15已经用完的账本不能重用。

计数覆盖表：Client的`connect_role`在明文TCP连接建立后、任何hello/setup前注册一次；
仅注册时读取本地/远端IPv4地址及native PID/TID/注册QPC。
同一个socket包装器拦截成功`send`/`recv`的实际返回字节，统一累计握手、setup、控制和停止流量，
包括4字节长度头；部分IO只计实际字节，EWOULDBLOCK/异常/EOF不虚增。
原`send_frame/_send_exact/receive_frame/_receive_exact`、双路交换与关闭握手均沿同一包装器，
高层不重复计数。TLS不支持此明文流映射。若绕过到sendall/recv_into/makefile等未支持入口，
标`unobserved_io_path`；第三条连接/重建、溢出、半帧开始、未知身份也不能冒充已知锚点。

每step两条连接各一固定行，保存请求起始/长度/完成偏移、回复起始/body长度/完成偏移，
未完成端点为-1。连接前setup偏移不丢弃，不把控制step0当TCP offset0；
round由原Client.json的step身份表解释。body只按长度跳过，从不保存或复制业务内容；
完整字节不代表协议已验证、已提交或已施力。
新增数值缓冲固定65536B（800行×64B），Client原983040B加起来1048576B，四业务进程总≤4MiB。
这些是诊断数值缓冲预算，不是整个Python进程RSS或原轻量timing的预算。
没有逐syscall列表、逐步写盘、额外线程或系统会话；结束后集中导出。

独立`Client.stream.json`使用`client-stream-map-v1`，不扩展旧`control-tail-diagnostic-v1`事件/manifest。
`stream-link.json`显式记录原manifest与sidecar原字节hash；sidecar另绑定原Client.json的hash、
公开diagnostic_id/head/protocol与round引用。旧D15分析器继续只读旧文件。
新的`experiments.windows_tail_analysis.read_stream_link`验证链接、身份、容量、重复/重叠区间、
原角色文件与manifest绑定；坏hash/round/越界直接拒绝，partial保留未知完成端点。

同模块提供`read_etl(path)`窄离线API：Windows x64消费者，非空文件≤64MiB、默认100000个事件，
仅显式`maximum_events=300000`可读取较长既有文件，硬上限300000，不自动重读或扩大。
遍历计数包括未知事件及超出解码预算后的事件；超限标不完整，不能截断后宣称完整。
只调用OpenTraceW/ProcessTrace/CloseTrace，设置文件名与RAW_TIMESTAMP|EVENT_RECORD；
文件头目前只接受64位布局；32位进程的事件指针仍按各条32/64位flags解码，WOW文件头布局未验证则拒绝。
没有实时session/provider启动API。原始QPC/正PerfFreq/trace终止与loss必须核验，
回调异常保留为不完整，finally关闭自己的读取句柄；未知事件不静默丢弃后宣称完整。
必要白名单为classic Process Start/End v2…4、Thread Start/End v2/v3、ReadyThread v2、
CSwitch v2/v3及TCPIP1074 v0/v1、1033/1300 v0/v1。每条仍用本机TDH核验实际字段名/type/flags，
不硬套历史AFD结构，不解引用内核地址或Buffer。TCB/进程键只输出本次局部ID。
字段版本不支持、连接地址/生命周期缺失或端点语义未证实时保留unsupported/unknown。
跨平台import不加载Windows DLL，普通D15分析仍可运行。

D132-18仅修读取已有ETL：原OpenTrace模式错误含`0x100`（REAL_TIME），导致离线文件
以无LoggerName的实时会话打开并报123；正确模式是`0x1000 | 0x10000000`
（RAW_TIMESTAMP | EVENT_RECORD），仍用Unicode路径和自有读取handle。
数值来源为[微软evntcons.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/evntcons.h)，
结构、union布局与模式语义依据[EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew)。
独立mock核查x64偏移/448B结构、112B记录、64位handle、中文空格路径及关闭顺序。
新增descriptor/unsupported/解码错误计数（各descriptor最多4096种），
来自Process/Thread/TCPIP的未支持计数与其他元数据分列；前者不表示每条都与目标线程相关。
不支持记录只读固定头，不保留其UserData，complete仍false，不忽略未知字段制造归因。
事件列表有显式数量上限、字段长度≤128B；这是记录数/字段边界，不是Python RSS硬配额。

已有01/02/03的真实文件可遍历208124/210554/208928事件，QPC频率10MHz、loss=0；
但CSwitch v5本机TDH返回1168、没有TCPIP事件，故Ready→Running及TCP覆盖仍未知。
Thread v3实际TDH验证仅提取ProcessId/TThreadId；不从v2/v3猜CSwitch v5布局。
读取修复不等于采集字段齐全，不为了归因打开新provider、重采或宽松解析。

原16A字段查询与合成oracle纳入本次软件核验：本机manifest字段存在、合成EVENT_RECORD解码、
mock API的头/loss/异常关闭与合成调度/TCP重组只能证明软件，不证明真实ETL事件会按预期出现。
**没有安全已有真实ETL，本轮端到端NOT RUN，未开始任何新跟踪/控制组。**
`normalize_schedule`要求Process/Thread完整生命周期，按nativeID解释Ready→Running；
`scheduling`必须接收完整规范化对象（events及complete），传裸events列表或complete不为True均返回unknown，
避免把不支持事件/解码错误的跟踪当可靠调度证据。帧覆盖保留首次完成时刻，但会检查全部相关同流事件，
覆盖后出现身份冲突或倒序也会使结果unknown；不同flow无关事件不污染该帧。
Running不能认定正在Python recv/GIL，等待原因不能单独指认socket。
整数QPC换算向下舍入<1ns只说明转换量化，不证明调度精度；跨A/B绝对ns不相减。

`correlate_frame`要求外部明确验证的同一新会话连接/全流seq零点/事件语义锚点，
以及sidecar可信body长度与偏移。没有这些就返回unknown，不能从首个数据包猜零点。
TCP覆盖仅表示指定系统事件边界观察到了连续字节，不证明TCP接受、socket可读或硬件到包时间。
拆/粘包、乱序/重传/appearance重复/重复ACK/回绕/缺段/混流与连接重建有独立反例；
SYN/FIN或半圈序号歧义不猜测。TCB连接映射候选字段不等于已经验证SeqNo运行语义。
外部锚点的`verified`是调用方的证据声明，软件不能据此发明真实运行资格，必须随报告附来源。

未来最小专项仍需单独用户批准：只A的ProcessThread/CSwitch/ReadyThread自定义collector候选
64KiB×128=8MiB，必要TCPIP元数据collector候选64KiB×64=4MiB；
不照搬内置CPU/Network大profile，不默认抓原始payload。实际buffer数量须查询核验，
内核工具本身和离线展开JSON不受4MiB业务缓冲限制。候选ETL每份64MiB、总磁盘256MiB，
预留至少1GiB；新控制≤400attempt/活动30s、原生窗口≤40s/总180s与退出预留均尚未执行。
有其他跟踪会话/过滤配置则停止本任务，不取消别人会话；WPR仅操作本次唯一instancename，
PktMon全局归属无法证明则不启动。不得拼接旧B trace与新A会话，未复现不补跑。
原生event版本/SeqNo语义、header时钟与安全无payload的源头配置通过前，不称ready-to-run。

## 两机慢步骤诊断（D132-15）

依据[本轮设计与授权](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6443216455)，
新增显式 `pair`（B端P1/P2）与 `client`（A端Client/原worker）子命令。
两端使用同一个已通过本轮独立审查的源码HEAD、审查链接、诊断ID与步数。
运行前退出旧Client动画和旧P1/P2；本入口是无窗口采集，普通演示入口保持原行为。
使用现有三个 `lab-*-cart-pole-demo.example.yaml`，不会替换实际IP/端口或改配置；
它们必须匹配同一个部署拓扑，Client为ready-v1，双方均无证书preauthorized-v2。
下载的示例已经保存B地址192.168.31.116；地址变化时按部署说明同步修改同一个拓扑文件。

软件独审通过后，在两机各自仓库根目录准备同样的三个变量（交付消息给出精确值）：

```powershell
$diagnosticHead = Read-Host '输入本轮独审覆盖的完整40位HEAD，两机相同'
$diagnosticReview = Read-Host '输入本轮独立审查评论链接，两机相同'
$diagnosticId = 'issue132-d15-two-host-once'
```

先在B端执行一次（不要另开普通P1/P2）：

```powershell
uv run python scripts/run_control_tail_diagnostic.py pair results/tail_diagnostics/d15-B --diagnostic-id $diagnosticId --expected-head $diagnosticHead --software-review $diagnosticReview
```

接着在A端执行一次：

```powershell
uv run python scripts/run_control_tail_diagnostic.py client results/tail_diagnostics/d15-A --diagnostic-id $diagnosticId --expected-head $diagnosticHead --software-review $diagnosticReview
```

默认最多400次attempt（软件测试可选`--steps 1…400`，两端一致），400次确认即按原停止协议退出，
没有401次控制或跨段继续维护。非实时诊断保留20ms模型，报告标记`non_realtime_diagnostic`，
>20ms只用于挑出慢步；真正连接/协议/材料等失败首错即停、不重试不确定事务。
Client首个采样开始后的活动窗口最多30秒；每端从启动准备至退出预算180秒，B等待人工启动A也计入。
监督在总预算177秒开始清退，仅对本次spawn得到的PID树操作，为清退预留余量；
操作系统调度/文件系统可能超出预算，真实超时或强退一律记不完整，不宣称硬实时保证。

`plan.json`先冻结实际HEAD、源码文件hash、脏状态、角色配置公开语义、部署摘要与本地时钟域。
`results/tail_diagnostics/session-诊断ID-本端.ledger.json`在启动角色前扣至0：
同一ID本端只启动一次，换输出目录也拒绝。B未连接、失败或没复现尖峰也不自动补跑；
不删除账本、不换ID绕过本轮一次授权，不消耗旧D10—D14额度。两端账本互不通信，
离线合并核验，无分布式exactly-once保证。

退出后将B端整个`results/tail_diagnostics/d15-B`目录复制到A端同一路径，保留文件原字节，再只读分析：

```powershell
uv run python scripts/run_control_tail_diagnostic.py analyze results/tail_diagnostics/d15-A/manifest.json results/tail_diagnostics/d15-B/manifest.json --partial --output results/tail_diagnostics/d15-analysis.json
```

不要加`--same-host`：A的Client/worker与B的P1/P2由各端真实spawn证明分别合轴，
两机绝对ns不能相减。双方HEAD/源码内容、拓扑、协议run/session/epoch及round不符会拒绝合并。
跨机源码文本摘要仅归一化`.py/.toml/.lock`的CRLF/LF换行差异；本机冻结/产物hash仍核对原字节。
每端manifest包含实际退出/强退信息、原角色trace与A全部≤400条计时；
`--partial`允许缺文件/失败前缀并明确不完整，坏hash或混配仍拒绝，不伪造未结束端点。
若Client在输入阶段失败、尚无本步round身份，partial保留原失败行和成功前缀，
单列`unknown_sample_round_steps`；worker预生成的材料round不替代Client事务身份。
已知round冲突仍拒绝，身份未知不能提升为完整证据；未显式partial的分析仍严格拒绝空round。
强杀可能来不及保存子进程trace，不能承诺强退仍完整。诊断原始产物与账本不提交Git。

报告覆盖全部完成步分布、失败样本、最慢8步、全部>20ms步及邻步；
A列应用send span和reply/frame/commit/output/applied点，B列各阶段及剔除嵌套后的时间、
本地suffix互等、GC交集和前后prefix/seed准备关系。B本地域GC依赖只表明局部等待贡献，
不能证明它与A的某一绝对时间重叠。不同主机只按步骤/round作因果关联；
Client总等候减服务器处理不能命名为纯网络延迟。应用收发不是网卡包时间，CPU零值不是网络证据。
每业务进程仍983040B、总计≤4MiB；GC/原阈值/启动清理与业务wire不变，退出才写盘。
观察可能改变分配与尖峰位置，本组不能当无观察净提速对照或严格20ms资格。
未复现如实报告，不补跑；抓包、原生跟踪、新修复/重测均不在本次范围内。

## 有界慢步骤诊断（D132-12，历史本机入口）

普通GUI/headless默认不启用该诊断，不分配事件缓冲、不安装GC回调。
显式入口 `scripts/run_control_tail_diagnostic.py` 提供 `local` 与只读 `analyze`，
复用原Client/P1/P2和原供料worker，未新增记录进程/线程或网络消息。
当前一次400步定位已获用户批准，必须先完成本轮软件独审；旧D11审查不覆盖本轮新head。
依据：[D12设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6435523226)、
[一次运行批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6435583866)。

软件独审通过并冻结head后，本机命令为（输出目录必须不存在）：

```powershell
$diagnosticHead = git rev-parse HEAD
$diagnosticReview = Read-Host '输入覆盖该head的D12独立审查评论链接'
uv run python scripts/run_control_tail_diagnostic.py local results/tail_diagnostics/d12-local --expected-head $diagnosticHead --software-review $diagnosticReview
uv run python scripts/run_control_tail_diagnostic.py analyze results/tail_diagnostics/d12-local/manifest.json --same-host --output results/tail_diagnostics/d12-local/analysis.json
```

`local`固定ready-v1、原preauthorized-v2/insecure_tcp、两测量observer、20ms模型、
非实时headless、段400和worker16；用隔离的127.0.0.1配置，不读取/修改用户LAN拓扑。
默认最多400个确认步（软件短测试可显式选1…400），第400次确认后请求原RunControl停止，
不发起401；sample容量不是停止条件。>5ms只是离线筛选标签，不能在102先停而漏285/290。
每次仅一组，24秒父收集和有界自身PID树清退，为30秒组上限留余量；实际超时、强退、
未知提交、导出失败均保留为失败/不完整，代码等待预算不是操作系统硬实时保证。
账本在任何角色启动前扣减；目录/角色文件/manifest拒覆盖，没有补跑/热身/恢复入口。
本次批准不含第二组、双机现场、native trace、未知修复或新性能资格。

每进程预分配12288×64B普通事件、2048×64B GC事件及64KiB身份表，
数字缓冲合计983040B≤1MiB，四进程≤4MiB；满容量不覆盖旧事件，标丢失序号及不完整。
热路径只写固定数字边界，不逐条JSON/写盘/排序，不记录share、seed内容、秘密状态/参数或摘要。
控制步与材料目标步分开；已有辅助线程保留native ID。协议层只接受可选公开callable。
GC回调记录start/stop/generation及活动控制阶段/线程/材料目标，不改变enabled/700/10/10，
不额外collect或枚举对象，保留原启动清理和其他GC回调，退出只移除本次回调。

角色文件使用`control-tail-diagnostic-v1`。实际本机spawn收据、父子PID和时钟实现核对通过，
才允许同域拼时间线；同hostname/相同人工标签不构成证明。不同域严格分轴，
未来A上的Client/worker与B上的P1/P2可以通过同一`analyze`入口关联协议身份/步骤，
不能直接相减两端ns或把Client减server叫纯网络。当前真实双机启动/运行仍不在范围内。

分析保留285/290、实际最慢及>5ms步骤和相邻正常对照。父子span列exclusive时间，
并行/GC重叠用同域区间并集，不重复相加；startup/stop/cleanup GC不计入真实控制窗口。
CPU记账可能量化，0不能证明网络等待；应用首次read/send完成也不是硬件到包时间。
证据分`Located`、`Contributor observed`、`Fixable mechanism confirmed`、
`Unresolved system/link wait`；GC重叠保留为事实，不替换按独占阶段得到的主定位。
只有主慢方矩阵GC期间对方已进入suffix等待、且慢方在GC后才进入同域交换时，
才记录该可核验依赖链的贡献；其他重叠保留未知，不确认可修复根因。
下一槽/辅助线程GC不冒充当前控制停顿。manifest声明`expected_step_count`，
同一分析器核对每步两路发送、材料claim/bind、服务器stage等必要事件；
缺整步/工作端点或未声明范围均标不完整，原因写入`missing_evidence`，不补造端点。
带观察的时间不与D11无探针结果直接比较净提速；观察可能改变GC触发步号，未复现就如实停止。
第399步为最终停止，与旧1000步继续维护不同。`plan.json`、`ledger.json`、四角色文件和
`manifest.json`保留源码/配置/时钟/退出/保存/hash事实；任何缺端点、满缓冲或保存失败均不造零。

## Client 双连接就绪驱动候选（D132-11）

这是显式选择的软件候选，默认仍为 `client_io: blocking-v1`。
在你选定的 **Client 配置副本**中加入顶层一行 `client_io: ready-v1`；
该副本还必须是 `transport: insecure_tcp`、
`wire_profile: control-dynamic-matrix-preauthorized-v2` 和动态持续 experiment。
P1/P2 保持原 v2 配置，不添加 `client_io`（服务器配置出现此键会拒绝）。
启动仍使用原 GUI 或 headless 持续入口，仅把 Client 配置路径换为该副本，例如：

```powershell
uv run python scripts/run_cart_pole_client.py configs/lab-client-cart-pole-ready.local.yaml --headless-continuous --non-realtime --recording light --segment-steps 400
```

上面的 `.local.yaml` 是用户准备的配置副本，不是仓库自带文件。保留三角色原有相同拓扑、
experiment 和 v2 wire；无需改 IP、端口、证书或网卡设置来启用此策略。
省略 `client_io` 或设为 `blocking-v1` 使用原路径。非法枚举、TLS/旧 wire、
静态/有限/完整路线及预送组合会拒绝，不会静默降级。四份用户现有 YAML 不自动修改。

`ready-v1` 在原 Client 线程公平推进两条连接，P1 背压不会阻塞 P2 开始发送；
两份请求完整发出后才按可用数据接收。每条完整回复立即验证真实提交事实，按角色保存；
P2 先到后 P1 超时仍保留 P2 已知提交。双有效提交先记账，随后输出检查、截止检查，最后才允许施力。
帧头/正文已有数据时直接继续，只有两路均无法推进才共同等待；不增加线程、进程或忙等。
同一期限覆盖两路全部分片与业务检查，退出尝试恢复两条 socket 模式；恢复失败终止会话。
失败不重发、不回退、不回滚已知提交。

本地策略不进入 permit、拓扑摘要或 wire，不改变服务器协议、数学、材料或普通步的四帧/一次因果往返。
`single_exchange` 起终点保持，包含发送、等待、解帧与提交核验，不是纯网络耗时。
结果 metadata 与紧凑持续终态记录 `client_io`；历史结果缺字段表示未记录，不能推定使用新策略。
本轮不增加逐步事件/落盘或扩大 raw 结构；行为证据由独立 I/O 模型和真实短功能会话提供。

**性能 NOT RUN。** 这是软件候选，不保证消除实测约 10 ms 相位现象或 80 ms 尖峰，
不能按两条连接推断耗时减半。新增两机有界对照须另行明确授权，不能把 sample-limit 当限步。
[D132-10 网卡方案](https://github.com/GNYKCZ/secure_pid_hvac/pull/141)保留草稿历史、目前暂停，
两端均未改设置、两组未运行；其额度不移给本候选，D10 的 6–8 ms 条件估计不适用于本轮。
完整契约见 [D132-11 设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/132#issuecomment-6395838844)。

## 无证书动态演示的显式选择

D132-9增加 `control-dynamic-matrix-preauthorized-v2`，复用下述单次往返计算路径，
仅压缩重复许可与输出编码。完整许可每步10份降为2份，其他消息严格绑定当前一步的公开引用；
双有效提交先记账、输出检查后才施力。三角色必须同时显式选择v2，禁止混装、回退或重试。
v1、seeded与默认均保留；三份配置、失败语义和准备摘要字段见
[D132-9候选](cart_pole_interactive.md#紧凑表示候选d132-9)。本轮软件验证不能证明尾部或两机性能改善，
新增性能运行尚未获授权。

D132-8新增显式`control-dynamic-matrix-preauthorized-v1`，需三角色同时选择。
它将普通Client往返缩为一次，并提前准备固定矩阵/已提交状态前缀；服务器按本步permit先提交，
Client核实双提交并检查输出后才施力。失败可能已提交而未施力，必须废弃会话。
旧默认及seeded保持；启用、启动命令、安全/失败与完整成本说明见
[D132-8候选](cart_pole_interactive.md#显式候选单次跨机往返及前缀准备d132-8)。

普通角色配置支持可选 `wire_profile: control-dynamic-matrix-v1`（本次两机推荐）或旧
`control-dynamic-compact-v2`，省略仍为 `control-batch-v1`。三角色必须显式选择同一版本，不自动升级。
P1/P2脚本将选择传给原协议owner，Client专用持续入口也使用同一协议，错配失败不回退。
仓库已提供三份配套 `lab-client-cart-pole-demo.example.yaml`、`lab-p1-cart-pole-demo.example.yaml`、
`lab-p2-cart-pole-demo.example.yaml`，均预设insecure_tcp和matrix-v1，Client预设两测量observer。
新演示显式使用这三份配置；原通用角色文件及脚本不带参数时的batch默认保留，不能混搭。
`transport: insecure_tcp`无需证书；TLS仍由独立transport选项决定，不能只删TLS配置字段隐式降级。
无性能要求的两机近直立演示使用专用脚本的 `--non-realtime --recording light`，动态profile、三角色配置及启动步骤见
[两机操作](cart_pole_interactive.md#无证书两机非实时动态演示)。保留Ts=.02、全部安全算术/双提交和仿真确认，不使用绝对周期钟。
动态持续light另有默认轻量性能汇总，可用 `--performance off|summary|samples`、
`--performance-output` 和仅samples有效的 `--performance-sample-limit 1..10000` 选择。
每步采集与截止判断独立，非实时旧miss仍为null；全程近似分位、明确失败/缺失和退出导出见
[性能报告](cart_pole_interactive.md#每步性能观察与结束报告132-阶段a)。该功能不增加P1/P2消息或更改数学协议。
compact/matrix即使关闭周期截止也先准备唯一worker及16份有界池，沿原owner补货和清退。
摘要区分实际尝试/提交/物理确认与worker清退；无周期记录时misses/last_cycle为null。
省略 `--non-realtime` 仍是原20 ms绝对截止模式，输出 `timing_mode=absolute`；
完整周期包含维护/记账。light的p50/p99/max只代表最近最多256条有完整端点的周期，不能冒充全程分位。
新模式不支持full、finite、预送、静态或完整起摆，原batch/full和实时功能保持。
这不是旧网络许可的延续，也不是20/40 ms性能验收、真实三机或硬件证据。
普通演示直接装配generic runtime，不借用或放宽network benchmark的固定N0/TLS/来源/占项门禁。

## S6 独立 worker 首轮通信定位（#120）

`benchmark --case cycle --mode batch --steps 20 --segment-steps 400
--material-slots 16 --preload-steps 0 --recording light --delay-ms 0
--worker-timeout-diagnostic --output <本次新结果路径>` 是独立诊断入口，隐式选择原worker。
不同时传S5 material-candidate、旧timeout-trace、diagnostic或GC-trial选项；旧门禁不放宽。
必须正常GC/原阈值、默认通信/ACK及原20ms。D6只批准唯一一次最多20周期，首错停，
启动/准备失败也消费该次调用，不重跑、不补步；软件检查和固定提交后的声明先于运行。

复用原304槽/每角色72KiB的socket/frame/GC探针，首错锁存在清理前，公开上下文只含
角色、操作、轮身份及序列。保存native调用起止/返回字节/部分进度/超时设置及读回/类别；
remaining与QPC/monotonic时钟对在调用结束后采样，不标成入口余量，不跨机器直接相减。
区分absolute_precheck、native异常、EOF及后续对端关闭，不把帧尝试计数当完整交付。
不记录秘密或异常消息，不写逐步诊断；原权威CycleTiming包括首步和失败/null端点及确认前缀。
P1/P2的GC边界与接收诊断包装各自固定前驱，同一次请求只委托原接收一次；
正常返回和原接收错误保持，退出还原全部观察钩子。软件修复不恢复已消费的运行额度。

S6由独立ExitStack持有恢复回调/角色队列，不依赖StartupGCTrial；初始化/运行/关闭失败
仍保留原错误并逆序恢复，附加清理失败拒绝成功。总诊断（含材料/GC/trace摘要）上限262144B，
输出声明实际字节、丢弃及恢复事实。`comparison_only=true`，qualification/stage/candidate门禁
始终false；20步全成功只算未复现，探针有扰动，不能替代1000/10000/完整路线或三机设备资格。
总预算不足时只保留首错/外层错与恢复事实、明确历史省略；必要时省略材料摘要但不丢周期，
预算失败拒绝资格，不把被省略的退出/内存事实补造为成功。

## S5 显式本机材料供料对照（#120）

`benchmark --case cycle --mode batch --steps 1000 --segment-steps 400
--material-slots 16 --preload-steps 0 --recording light --delay-ms 0
--material-candidate thread|worker --output <本次结果路径>` 只选择实验候选；
不改变正式 CLI/GUI/配置默认。S5批准范围为同一提交先thread一次、再worker一次，
各最多1000尝试，首次失败停止；初始化失败也保留，不补步、不重跑或筛选参数。

worker在Client本机用一个spawn工人生成原Beaver/Trunc及静态JSON片段，
两个单向私有Pipe只传有界字节/累计前缀额度。父接收器核对身份、计划摘要、
尺寸/完整性/步号/额度后登记父进程一次性能力；当前测量由原Client量化/检查/分享，
父进程拼装的两份完整信封均预检后才发送。工人不持测量、控制参数、秘密state、
控制socket或输出签发表，不pickle业务对象，不恢复父进程秘密DTO树。
双方仍用原动态后端、旧state出力、逐行Trunc、原重构、双提交及设备确认。

库存与生成/IPC在途合计最多16份，每份预留512KiB，总编码预留8MiB；
当前已领取轮、IPC临时副本单独报告。这不是RSS上限。Client/worker各受256MiB
离散内存保护；采样不证明瞬时上限或长期无泄漏。控制线程不等待Pipe/补货，
短缺、工人/通道故障、部分帧、超期及未知提交封闭当前run，不重启/重试/fallback。
停止废弃库存、五秒内join工人与接收/额度线程；强制终止或缺最终汇总记清理失败，
不能通过候选门禁。材料不写磁盘，不跨运行缓存。
关闭观察或清理异常不覆盖已发生的协议首错；`material_comparison`中的
`memory_sample_error_type`/`cleanup_error_type`只附加公开异常类别（无消息），
同时保留保护/清理失败标志。关闭层延后到原runner结果返回后统一判定，不以异常栈是否为空
判断有无首错，不丢已形成的周期与确认前缀。无先前错误时保护或清理失败仍使对照失败，
不能通过候选门禁。

正常GC/原阈值，保留原启动收集，不freeze/disable，也不安装S3/S4 socket或GC事件探针。
仅控制开始/结束读取GC统计；worker按开始命令接收和停止读取，P1/P2以第一online请求
及stop请求（故障时退出）为边界，不把这些非同步时钟边界作单向网络时间。
只在结束输出轻量公开汇总，保留所有权威CycleTiming的尝试、失败与null端点。
`comparison_only=true`，`qualification_pass/stage_pass=false`；
`candidate_gate_pass`只在worker完整1000步零超期/故障、状态/跨段/资源连续且清理成功时通过。
1000未发生整代GC可能仅推迟扫描；不是10,000、完整路线、三机Wi-Fi或硬件验收，
也不自动推广默认、追加试验、合并或关闭Issue。

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

### 动态持续控制的记录模式与通信（#120）

动态 observer 的专用 GUI 与 `--headless-continuous` 默认使用轻量记录；
显式 `--recording full` 才启用完整留证。静态、有限步和完整起摆路线维持原服务，
不接受这个模式选择参数。记录模式不修改协议、材料、安全检查、设备确认或20 ms截止时间。

light 只在内存保留首周期、最近256个公开周期和失败摘要，停止后才整理窗口统计；
窗口分位数不代表全程。正常停止返回 `status=stopped`、`recording_mode=light`、
`evidence_state=not_recorded`，run_dir/prefix_dir为空，durable_step_count为0。
没有轨迹/哈希链/读回/写盘/图或正式回放。GUI按钮为“停止”，保留最后确认画面与计数，
显示“未保存完整实验轨迹”；failed/uncertain/cancelled仍显示真实失败类别。
full 继续原严格记录、可靠前缀、读回、停止保存与正式回放契约；磁盘失败不降级成light。
静态入口的默认记录服务不变。

所有真实TCP拨号和接受连接在建连期设置TCP_NODELAY，TLS包装保留该设置；设置失败关闭
连接。它减少可能的小消息等待，不减少应用帧，也不保证操作系统/无线网络尾延迟。
只有batch、非零秘密状态、lan-segmented-v2的独立动态持续路径先发送P1/P2原commit请求，
再依次核验两方ACK；full-v3、有限/静态和旧后端保持串行提交。两份有效ACK是出力门槛，
未知提交不重试、不回滚、不继续下一轮。last_commit_observation的false只表示未收到有效ACK，
不能推断远端未提交。协议双确认、物理确认与可靠前缀仍是不同事实。

overlap的公开阶段键为p1/p2_commit_send、commit_ack_wait、commit_latency；两方latency
存在重叠，不可相加当总耗时或称网络RTT。原serial的p1/p2_commit含义保持。

benchmark cycle为兼容历史负载仍默认full，需显式 `--recording light` 测量轻量控制。
light的writer/drain/fsync/checkpoint指标为null（未执行），来源检查仍实际执行并计时。
基准保存至多10000个周期用于停止后单次输出，区别于生产256窗口；最终周期以runner终止
事实校正，不能用回调中临时的confirmed覆盖回调后超期。
仅内部三进程cycle接受 `--tcp-nodelay off` 或 `--commit-policy serial` 的受控对照；
外部role-config及其他case拒绝非默认策略。报告各角色建连期实测socket选项、实际提交策略、
comparison_only和来源摘要。非默认对照不能取得production qualification_pass。

本轮同SHA各一次A（light/off/serial）、B（light/default/serial）、C（light/default/default）
1000步、segment400/preload1000/fused/delay0，新run/new材料、首次失败停止。C零超期才运行
默认16槽无预送1000；再通过且长期条件合法才10000。首个C/默认供料失败最多一次原有限
诊断，steps=min(首次失败尝试数+5,1000)。不重复挑绿，不用预送库存冒充持续供应资格；
本机仿真通过也不代表完整起摆或真实三机Wi-Fi/硬件资格。

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

限定启动GC试验使用 `--gc-trial-policy baseline|startup-freeze`，默认不启用。
只允许独占、运行一次即退出的Client主进程，以及cycle/batch/light/diagnostic、
1000步、段400、16槽、无预送、零注入延迟和默认通信策略；非法组合先拒绝。
自动GC必须开启，永久代、调试标志和外部callbacks必须为空。必要依赖导入后，
在端口、角色配置、进程/队列、会话、场景和材料创建前，两组各做一次冷启动完整GC；
startup-freeze再冻结当时全部受跟踪对象。运行中新对象仍正常GC，原运行时startup_gc保留。
冻结不保证对象不可变，也不能直接用于GUI或正式入口。

公开 `gc_trial` 分开记录冷GC、freeze计数/耗时、原startup_gc、GC统计采样时刻、
退出恢复和当前/峰值OS内存。控制开始/结束及g0/每100步输入前检查当前RSS 256MiB保护线；
不可用或超限按原异常停止，采样开销计入原期限，不能排除采样之间的瞬时超限。
材料8MiB编码预留不是RSS上界。详细区间保持g0..1、165..168、176..180；
Client GC配对覆盖整个试验（含初始化/关闭，以control_active区分），P1/P2窗口不扩展。
GC stop保存collected/uncollectable计数，缺失配对与overflow明确报告；仍共用每角色512槽、
72KiB事件预算，全部诊断及策略摘要共256KiB。退出集中写JSON，不按周期写文件。

退出先执行原池close/5秒join/discard并移除自有诊断钩子，再解冻自有永久代、
恢复GC设置；只有供料线程已退出才做停机收集。清理失败单列且不能覆盖原控制失败，
不能继续建池或重试。S2获批预算为同一固定head先baseline后startup-freeze各一次、
每组最多1000尝试且首次失败即停，总计最多2000；安全/数学/所有权缺陷取消第二组。
两组均为comparison_only/diagnostic，qualification_pass和stage_pass均false；
即使1000步无miss，也不替代默认持续供料门禁、10000步、GUI或三机验收。

S3为另行批准的单次定位：`--timeout-trace`与startup-freeze及200周期、
cycle/batch/light/diagnostic、段400/槽16/无预送/零注入/默认通信的本机三角色组合。
S4另行批准baseline的同一严格200周期组合，复用相同探针及预算，只有启动GC条件不同：
一次cold collect和原startup_gc保留，不freeze/unfreeze、disable或改阈值。
baseline仍是有额外冷启动清理和观测的诊断条件，不等于正式默认资格；
S3预算已用尽，S4仅一组一次、最多200尝试，初始化失败也耗用机会，不追加冻结对照。
False不安装socket探针；S2不带该标志仍严格要求1000周期。新探针在冷GC及可选freeze后创建，
仅在原send_exact/receive_exact调用参数处透传同buffer、参数、返回及异常；
不改socket算法、blocking、原cursor或deadline，不加重试/业务重发。每角色最多4探针、
8条公开上下文，只有角色/操作/session/round/step/sequence等白名单标量，
没有payload、信封/异常对象、消息文本或repr。接收上下文可能只是末次请求的预期回包，
或上次实际收到的信封；明确标注来源，不冒充当前回包已验证。

事件列schema只导出一次；记录原settimeout秒值、实际gettimeout值、原deadline秒/ns与域，
以及Python调用边界QPC起止、调用后QPC→monotonic_ns→QPC采样对、已返回的字节数。
remaining_ns只在相应QPC或monotonic域计算；legacy浮点秒转ns有舍入，不能跨epoch减。
first_failure锚点在清理前，区分absolute_precheck、socket_send、socket_recv或unknown；
外层和直接cause仅公开类别与整数errno/winerror，异常native调用的部分进度明确unknown。
时点包含探针开销，不能看到C内部重试/内核路径，线程CPU量化不证明GIL归因。

S3/S4固定环为128 socket/64 frame阶段/64 GC/32 producer/16首错与关闭，共304槽，
活跃配对最多16，仍受每角色512槽/72KiB、总256KiB（含GCtrial摘要）保护。
各环正常淘汰evicted_count与导出encoded_omitted分别记录，公开实际最早保留时点。
首个Client终止错误立即锁存；随后正常停止流量不挤掉现场，只保留在途GC/补货结束和有界close。
正式QPC续收中的would-block及TLS WantRead/WantWrite仍记录原生事实，但不锁存/停记；
只在当前线程、当前QPC接收通道内区分，旧float接收和发送中的终止错误保持原首错语义。
旧固定窗口不叠加；保持原RSS256MiB、g0/g100与启动/结束/恢复检查及GC/钩子恢复。
仅在固定提交推送、发布预声明后运行一次最多200周期，首失败停，退出一次集中输出。
失败/缺测/省略/未复现均不重跑，不复用剩余上限、不加对照或参数扫描。
S4未复现或关键区间缺证时定位未完成，停止新增运行与自动往返交接，不制造后续试验。
diagnostic/comparison_only=true，qualification/stage=false；200成功不代表正式冻结可采用，
也不替代1000/10000、跨段、完整路线/GUI、网络、三机或硬件资格。

### 显式 worker 长期候选（S9）

`--worker-long-run` 默认关闭，只续接现有 worker，不改变正式线程供料或 GUI。
原 `--material-candidate` 仍固定 1000 周期，`--worker-timeout-diagnostic`
仍固定 20 周期。S9 仅接受 cycle/batch/light、严格整数 10000 周期、段 400、
16 槽、无预送、零延迟、内部本机角色、默认 TCP/双提交和正常 GC 700/10/10。
冻结、禁用、调试 GC、外部 callback、诊断/trace/GC-trial、外部 role-config、
候选选择或通信策略覆盖均互斥；非法组合在端口、材料、进程创建前拒绝。

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 10000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --worker-long-run --output .tmp/issue120-s9-worker-long-run.json
```

[D9 批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6144849748)
覆盖限定入口/门禁/测试/文档实施及新 SHA 必要软件检查、独立核查；只有该软件
部分无确认缺陷并获准进入验证，才可发布预声明后使用唯一一次最多 10000 尝试
的预算。初始化失败也耗用机会，首个失败即停，不重跑、补步或加对照/探针。
输出必须是新文件，不覆盖 S5–S8 原件；失败后的新修复/测量另需具体决定。
累计自动返工仍 3/3，不自动第四轮，不合并或开始下一阶段。

有效配置仍为 `cart_pole_observer_lan.example.yaml`。原小数 32 bit、lambda80、
参数/运行 payload 40/46 bit、256 bit 素数和 n4/m2/p1 不变。持续装配使用
`sustained_observer_numeric_contract` 的 `bounded_input_reachability`，
`horizon_steps=None`，原精确编码块幂证明覆盖有界输入下任意轮次并含截断误差。
原 Client 仍在控制前验证范围、累加器和截断界，每轮检查输入，场景守卫保留；
不延长有限证书、不重建初态或跨段清秘密状态。只公开证明模式/算法/位宽摘要，
不导出矩阵、编码初态或秘密状态。数学范围证明不是物理或硬实时无限期保证。

10000 个完整周期从原计划起点计至软件设备确认、记账与观测出口，均须严格
小于原 20ms 期限。g399、799…9599 共 24 次继续控制的段维护计入对应周期，
不刷新时钟或期限。g9999 设备确认和记账仍受最后周期保护；之后正常停止的
末段 END/双方停止确认、终止 source 复核、关闭和结果导出属于周期外停止流。
不能称停止握手也在 20ms 内，不能用退出耗时倒推周期完成。停止必须成功：
缺双方关闭确认、来源复核或清理失败均拒绝长期门禁，即使控制周期全部按时。

`worker_long_run` 元数据含版本 1、目标/最大尝试 10000、条件及持续数值契约
摘要；初始化失败也保留模式和原失败周期/类别。`worker_long_run_gate_pass`
要求全分母、连续步/段/身份和唯一 round、原计划/期限/确认前缀、双方各步对应
round及末步双 ACK、10000 次材料领取、库存+在途≤16、编码≤8MiB、原内存保护
及全部供料进程/线程有界退出。材料消费为300000次乘法/40000次截断，多余库存
停止废弃。所有首步、慢步、跨段和失败/null端点保留，不能只看平均值或p99。

原 Client/worker 256MiB 离散当前 RSS 保护线不提高；worker 内存 deque(maxlen=32)
和 16KiB 结束摘要保持。benchmark 最多保存10000尝试、生产近期窗口仍256，
它们不是无限期内存证明。light 不在控制期间新增写盘或存储材料；退出后沿
既有方式一次导出公开结果，不承诺一次物理写入。离散采样和各角色 GC 边界
也不能定位逐 socket 错误、证明瞬时总内存或排除未来尖峰。

长期候选通过时 `candidate_gate_pass=false`，`comparison_only=true`，
`qualification_pass=false`、`stage_pass=false`。结果只适用于声明 SHA/配置/
环境的本机 worker 动态长期样本；不是正式默认推广、完整路线、认证三机
Wi-Fi 或硬件施力资格。未开启重 socket/GC 事件探针，历史 S5 根因仍可能未知。
完成后发布完整原件/hash与实际结果交回 Design，停止，不自动追加运行。

### 显式 worker 在线确认链定位（S10）

`--worker-wait-diagnostic` 默认关闭，独立接受 cycle/batch/light、4000周期、段400、
16槽、无预送、零注入、内部角色、原TCP/双提交与正常GC700/10/10。
与所有其他候选/诊断/trace/GC选择及外部配置/通信覆盖互斥，严格类型检查在
端口/材料创建前完成。S5/S8的1000、S6的20、S9的10000入口限制保持。

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 4000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --worker-wait-diagnostic --output .tmp/issue120-s10-worker-wait-diagnostic.json
```

[D10批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6146925091)
仅授权四文件诊断续接，必要软件验证和独立核查通过后，先预声明新完整SHA、
有效来源/配置/数值/初态/依赖锁/环境时钟/正常GC及完整命令，再仅运行一次，
最多4000尝试，首次失败停。准备/启动失败也消费；不预热、补步、重跑或加对照。
输出必须是新文件，不覆盖旧原件。3/3不重置，不自动第四轮修复。

复用原worker及持续证明（reachability/horizon=None/block19），不改输入、秘密
状态、材料新鲜性、截断/模数/位宽、安全校验和online→stage→重构→双提交顺序。
20M ns绝对期限、迟采样占预算、继续段维护计入周期，正常停止握手/退出/导出
仍在周期外另计且必须成功；失败关闭不能冒充正常停止或周期完成。

新增探针profile为`worker-online-wait-v1`，角色报告`format_version=2`。
原trace `values`/`schemas.trace`字段仍在调用后采样，尤其`remaining_ns`仍不是
入口预算。新增`schemas.entry`定义调用前固定快照：操作、peer、方向、header/body、
时钟域、deadline、`remaining_at_entry_ns`、请求/实际timeout_s、`native_called`、
请求字节/之前确认字节、线程及可确认公共上下文。QPC/monotonic/QPC配对在调用前
读取；legacy剩余时间按monotonic计算，不能把跨时钟域值直接相减。
canonical timeout precheck前也采样；其后才可能耗尽预算，因此入口正余量不保证
原precheck或调用返回时仍有余量。预检异常`native_called=false`，实际send/recv为true；
失败实际进度未知，不由请求字节数推造。每socket只保留当前入口，角色首错入口
`first_failure_entry`锁存；普通native事件的entry进入原滚动socket环，不无限累计。

Client分别记录`online_wait_P1/P2`；服务器记录完整body返回时身份未知的标记、
decode区间及online解码返回标记、`material_restore`及`online_ack`区间。
服务器收帧/解码前不使用上轮身份；解码成功后才登记当前公开身份。两层phase过滤
都支持这些事件。正常GC callback仅记录起止、线程CPU/墙钟和公开计数，不主动
collect/freeze/调阈值；生产事件沿用原观察入口。没有采集worker内部GC或内核状态。

每角色共享304槽/最多4socket、72KiB角色报告、256KiB额外诊断合并预算保持。
入口快照、schema和首错也计入编码预算；滚动淘汰、编码省略、未配对GC及未知
上下文如实保存。完整CycleTiming/逐步原件另计，不能说整份JSON≤256KiB。
原Client/worker离散256MiB、库存+在途16、预编码8MiB保护保持。探针会有开销；
不能将有探针S10与无探针S9当严格性能收益对照。原函数调用次数/参数/返回/异常
透传，退出恢复hook/callback，首错不被关闭覆盖。探针/预算/清理错误拒绝成功。

顶层`worker_wait_diagnostic`含版本1、最大4000、实际尝试/失败、预算使用及持续
数值摘要；初始化失败也保留。`diagnostic=true`、`comparison_only=true`，candidate/
worker_long_run/stage/qualification均false。即使4000全成功也只报“未复现”，
不授予10000、正式默认、完整路线、TLS三机Wi-Fi或真实设备资格。
退出后保存全部尝试及失败null端点，公开可恢复完整原件/hash和时序证据，交回
Design分析后停止。GC重合仅是线索、低CPU大等待不证明网络/GIL原因，ACK发送
返回不等于Client已收到，软件设备确认不等于硬件施力。

### 正常 GC 下的有限服务器候选（S11）

`--server-gc-candidate` 默认关闭，严格独立接受 cycle/batch/light、4000周期、
段400、16槽、无预送、零注入、内部角色、原TCP和双提交。使用既有worker；
与S5/S6/S9/S10、GC试验、重诊断、timeout_trace和配置/通信覆盖双向互斥。
选择必须为严格bool；GC须enabled、700/10/10、无冻结/debug/外部callback，
错误选择在创建端口和材料之前拒绝。原入口的20/1000/4000诊断/10000限制保持。

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 4000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --server-gc-candidate --output .tmp/issue120-s11-server-gc-candidate.json
```

[D11批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6148905058)
授权六文件限定优化与软件/独立核查通过后一次最多4000尝试的验证。先发布并
全文读回新完整SHA、来源/配置/依赖/初态/持续数值证明/环境时钟和唯一命令；
输出/日志必须尚不存在。启动失败也消费预算，首次失败立即停，不预热、补步、
重跑或加对照；3/3不重置，新有效Finding不触发自动第四轮。完成后公开全部
尝试和可恢复原件/hash，实际交回Design只读分析后停止。

canonical codec只减少固定字段校验的临时对象，公开字段名为不可变常量，
不缓存秘密值/DTO。schema3和原编码字节、重复键/UTF-8/有限值、深度/数量、
完整字段集合（含同数异名）、严格类型/shape/decimal/资源身份检查保持。
候选P1/P2在有效offline材料恢复、角色/recovery装配后、原offline ACK前各
仅主动`gc.collect(2)`一次。清理失败不发伪ACK；lan_ready、online、commit及
跨段不重复主动清理。Client原准备及t0边界保持，正式入口GC策略不改。

新增轻量profile `server-gen2-light-v1`只保存正常gen2的公开QPC起止、线程、
generation/collected/uncollectable；没有当前round/step身份，明确unknown。
每方64完成区间+1pending、32KiB/角色，合并96KiB含元数据，全周期/raw另计。
淘汰/未配对/编码省略/已观察最大值另报；启动主动清理单列，不算运行期覆盖。
运行中不遍历对象、读locals或秘密值、编码JSON/写盘，不安装S10逐socket/frame/
阶段探针。退出恢复callback及hook；观察/编码/内存错误拒绝候选且不覆盖原首错。
原材料库存+在途16、预编码8MiB、Client/worker及新增子角色离散RSS256MiB、
原有界退出保护保持；离散RSS不是瞬时峰值或长期内存证明。

`server_gc_candidate`元数据version1公开target/max4000、实际尝试/失败、预算
消费、两方启动清理、运行期gen2覆盖和观察预算。`diagnostic=false`、
`diagnostic_report=null`、`timeout_trace=null`表示没有旧重探针，新增轻量GC
观察仍存在。新`server_gc_candidate_gate_pass`须4000全部有效按时确认、零miss、
唯一身份与连续确认前缀、120000乘法/16000截断、原持续reachability/horizon=None/
block19证明、9次继续维护g399…3599在原20M ns周期内，以及最后周期和原正常
停止/双方ACK/worker退出成功。迟采样占原预算，不刷新deadline。

`runtime_gen2_covered`独立报告：两方完整保留控制窗口内gen2且没有淘汰/未配对/
省略才支持覆盖此类暂停。未发生或记录不完整时，即使有限门禁通过也不能说
长期GC风险已经验证；启动清理可能只推迟首轮暂停。两项优化共同候选、无同SHA
A/B，不分配单项收益。始终`comparison_only=true`，旧candidate/worker_long_run/
stage/qualification保持false。原10000、完整路线、认证三机网络和硬件验收仍需
独立完成，软件设备确认不等于真实施力，不据此推广正式默认或合并PR。

### 计算阶段与首个通信错误定位（S12）

`--stage-wait-diagnostic`默认关闭，只允许独立cycle/batch/worker/light、4000周期、
段400、16槽、无预送、零注入、原配置/初态/持续proof、默认TCP/双提交、正常
GC700/10/10/freeze0/debug0及无外部callback。严格bool及互斥检查在端口/材料创建
前执行；与S5–S11及通用diagnostic/timeout_trace/GC试验/外部配置和通信覆盖双向
互斥。原预算不放宽，不能与`--server-gc-candidate`同时选择。

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 4000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --stage-wait-diagnostic --output .tmp/issue120-s12-stage-wait-diagnostic.json
```

[D12批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6162360598)
只授权四文件定位及软件/独立核查通过后一次最多4000周期。先发布并全文读回新
完整SHA、来源/配置/依赖锁/初态/持续proof/输入策略/环境钟域/GC和观察预算及
完整命令，新raw/log不得已存在；启动失败也耗预算，首失败停，不预热、20步、
补步、重跑或第二组/无探针对照。D11已用完，3/3不重置，新有效Finding不自动
第四轮。完成后公开全部尝试和可恢复原件/hash，交Design只读分析后停止。

复用S11两服务器offline ACK前各一次collect2及正常gen2观察；Client原启动清理
不改。Client新增gen2报告另标`client-gen2-light-v1`，可能包含t0前原启动区间，
不能把它算运行覆盖；服务器保持原`server-gen2-light-v1`语义。GC仍64完成+1pending。
只补Client原start/finish_stage_batch、服务器原stage/批量peer交换/计算回执区间，
方法入口与原返回/异常分列，原返回表示原验证已完成，收齐body并不等于验证。
透明复用原socket包装与canonical framing，原buffer/deadline/参数/返回/异常一次
透传，不多读、不重试、不改变blocking/cursor。回执send返回不是Client收到。

每角色128个stage滚动事件、4连接在途槽、1独立首个I/O错误；非stage I/O不存
滚动历史，只保留当前framing的最新入口与独立首错。调用已返回/报错的事件不
标为native仍在途；部分帧的已确认字节与失败native未知进度分别保存。原precheck
失败native_called=false；真正send/recv入口为true，不由事后余量倒填入口预算。
每次只作必要QPC/legacy单次读值，无S10 CPU/每次双钟配对/全阶段重探针。

公开字段限定时间整数ns、枚举、线程、限长身份、peer/方向/header/body、字节进度、
deadline域、入口余量/timeout及错误/cause类别/errno/winerror；不读对象图、locals、
秘密值、任意异常文本或traceback，不在控制中JSON/写盘。服务器解码前身份未知，
stage只用当前已验证plan/request的期望身份，期望不等于收到的帧已验证。legacy保护
按原monotonic计算、QPC单列，不当周期deadline，也不直接跨主机相减。

`stage_wait_diagnostic`格式1/profile `stage-wait-light-v1`包含三角色schema、去重
公开身份表、阶段记录、独立首错/外层错、close锚点、原gen2及丢失/恢复状态。
stage+GC+元数据每角色64KiB，合并192KiB（含诊断描述字段），全部CycleTiming/raw另计。普通环淘汰
及编码省略单列；超预算会压缩普通历史而保留首错，并标证据不完整。观察/编码/
恢复/GC状态/内存/退出错误不覆盖原控制首错。只判evidence_complete、控制故障及
首个I/O错误是否观察到；无故障也只是有限未复现，不称修复或定位成功。

`diagnostic=true`、`comparison_only=true`，原S11有限gate及candidate/worker_long_run/
stage/qualification均false，timeout_trace=null表示没有旧全量trace。原20Mns绝对
周期、迟采样/继续维护占预算、正常停止另计、16库存+在途/8MiB/256MiB/有界退出、
一次性材料/秘密状态/原精度/模数/输入守卫/reachability horizonNone block19/双提交
和过期输出拒绝保持。新观察会影响分配和故障轮，不是无探针A/B；并行/嵌套区间
不能相加为独占成本，不排他归因OS/GIL/内核，不推广默认或替代原长期/三机/硬件验收。

早期有限诊断预算为fused/stock1000/段400的零注入406步和1ms每帧1步，各一次，现已使用，不能复用；
失败即停，退出集中输出。未复现也不得循环追样本或用诊断PASS代替1000/10k验收。

- `configs/lab-p1.example.yaml`、`lab-p2.example.yaml`、`lab-client-continuous.example.yaml`：三个独立角色入口。
- `configs/local-deployment.example.yaml`：三条连接的地址和端口；三台电脑内容须一致。
- `configs/paper_pid_lan.example.yaml`：Client 日常参数，直接读取 `paper_pid_cascade_zoh.yaml` 和共享素数证明；不依赖 Fig3 四点定义，运行声明为 `user-exploration`。
- `configs/paper_pid_fig3_sweep.yaml`：四点图独占的冻结定义，仍读取历史名 `hvac_2r2c_sweep_prime.yaml`，因为已发布 Fig3 清单绑定文件名和原始 SHA。

旧 LAN/TLS 示例配置和 VS Code 调试清单已移除。历史 HVAC 配置仅留在 `tests/fixtures/legacy_hvac/` 供内部回归；它们不是日常实验入口。正式 `results/paper_pid_fig3/` 证据和四点 reader 保留。三角色与 Fig3 复用同一个 paper PID 场景计算，不复制安全协议。
## S13：有限实验历史的紧凑表示

`--compact-history-candidate` 默认关闭，仅用于显式批准的本机
cycle/batch/worker、4000 steps、400 segment、16 slots、preload0、light、delay0。
它与 S11/S12 及其余试验/诊断/外部角色或通信覆盖互斥，严格 bool 和形状检查在端口、角色、材料之前完成。
正式 light 的 256 近期窗口和段内 400 记录不变；本候选改变的是实验层全量历史表示。

Client/P1/P2 在各自控制开始前分配固定 `bytearray` 行表。Client 的 steps/cycles
各 4001 槽（含失败/尾部预留），phase events 为 16×4000+64 槽；P1/P2 各 4001 step 槽。
公开字段白名单及布局在启动前确定，不扩容、不循环覆盖、不保存输入 DTO 或完整嵌套树。
控制回调直接读取原公开标量，原 meter 的计数/分项仍使用原一次调用；不先 asdict/JSON/pickle
整棵输入对象。原 runner 自身的必要有界状态与校验没有因此移除。

每字段独立区分未出现、None、实际值；整数 ns/count 检查后按无符号 64bit 保存，不经 float；
毫秒保存为原 binary64，不舍入、不转 float32；UTF-8 显式检查字节长度，不静默截断。
全部字段写完才发布有效行计数，未知字段、重复字段、非法父映射、容量/类型/范围/长度错误停止捕获。
半写入行不发布，已完整捕获前缀保留；展开损坏只返回完整行前缀，并明确不完整。
错误只记公开类别，不保留异常对象、任意错误文本、份额、材料、矩阵、对象图或分配栈。

当前启动布局：Client buffer 12,257,607B，加固定元数据保守上界 524,288B，预留上界
12,781,895B；P1/P2 各 buffer 1,348,337B，加同样元数据上界，各 1,872,625B。
三角色合计预留上界 16,527,145B，分别小于每角色 16MiB、合并 48MiB。
元数据上界是固定字段表/计数/登记/报告的保守预算，不是测得 RSS 或额外物理 arena。
预分配与展开分别采样原 OS RSS，原离散 256MiB、材料库存+在途16和预编码8MiB保护不放宽。
捕获时间仍在原20ms预算内；控制停止、S12 hooks/callback卸载后才展开/汇总/写盘，展开耗时单列。
JSON编码及独占文件写入的退出后耗时另存命令末行 `history_export_ns`（运行log），不倒填为周期成本。
原 `_correct_cycle_tail` 在退出展开后处理同身份权威尾部；不另造控制成功数或把 miss_after_apply 改为成功。

仅在原材料工厂成功装配后读取 control/receiver/credit 的 PID、native ID、ident 和观察生命周期，
保存标量，不保存线程对象。原 close 后读取已有 receiver/credit 的存活状态；控制线程的 observation_end
表示观察结束，不谎称控制线程此时已经退出。登记早于 GC start 且 GC end 早于观察结束、PID/native
匹配时才标明线程角色，否则保留未知；这不证明触发分配的函数或独占 CPU，也不反改 S12 的旧线程14320。
材料生成、接收、公开计划/片段校验、摘要和 IPC 格式保持原实现，无新进程、依赖或模块。

内部复用 S12 stage-wait-light-v1、每方128 stage环/4在途/独立首错、GC64+1及三方192KiB观察预算；
非stage成功 I/O 没有新增全量历史。Client原startup、P1/P2 offline装配后ACK前各一次collect2保持；
运行GC enabled700/10/10/freeze0/debug0，不冻结/禁用/改阈值/主动运行期收集。
新 `compact_history_candidate` version1 明示尝试/失败/消费预算、布局/捕获与展开、首错/线程及GC覆盖，
`diagnostic/comparison_only=true`；所有原 S11/candidate/worker_long_run/stage/qualification flags 为 false。
`finite_sample_pass` 单独检查4000按时完整、原身份/数值/材料/资源、9次继续维护、正常STOP双ACK、
worker/receiver/credit退出与完整恢复。无运行 gen2 只能说未覆盖，不能说GC成本降为0。

GC分类版本2使用Client原on_cycle正常confirmed出口的私有QPC锚点与终末STOPPING入口；
继续段ENDING_SEGMENT仍属原控制周期。完整GC区间须全落在已证实的控制/观察范围且原观察证据完整，
才贡献`runtime_gen2_coverage=true`。正常停止、启动外部、跨边界或末观察到STOPPING间隙分别标为
`normal_stop`、`outside`、`overlap_or_unknown`，全部原区间及线程匹配保留。缺失/乱序锚点不能
退回最后计划deadline；失败I/O和清理不延长已确认观察范围。原callback成本及miss_after_apply保护不变。

仅软件和新head独立核查通过、目录释放、完整预声明发布且全文读回后允许：

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 4000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --compact-history-candidate --output .tmp/issue120-s13-compact-history-candidate.json
```

一次最多4000，启动失败也消费，首失败停，不补步/重跑/预热/额外20步/第二组/对照。
旧预算不复用；全部成功/慢步/失败/null、阶段事件和双方逐步记录退出后完整导出，可恢复原件和hash。
观察或展开失败不覆盖原控制首错、不获得完整/PASS，不靠再次运行恢复证据。
正常GC、算法/协议/精度、20ms及正式默认不变；新旧SHA/随机负载不同，不是同SHA A/B。
即使有限样本通过，也不授原10000、完整路线、认证三机或真实硬件资格，不自动进入下一试验或合并。

## S15：实验 Client stage 回复观察（历史D15预算已消费）

`--qpc-stage-receive-candidate` 默认关闭，只有显式获批的 cycle/batch/fused/worker/light、
delay0/preload0、slots16/segment400、本机 insecure_tcp、1..1000 steps 可用；与其余诊断候选互斥。
S15原始SHA没有改变正式transport；当前S17已将算法移到canonical owner，见下一节。
此选项仅在Client的`finish_stage_batch`、当前P1/P2原通道与同一`_CycleDeadline`上增加公开观察，
委托与正式路径相同的收齐实现；非该阶段走canonical默认。未知身份、通道、TLS或legacy deadline不纳入此实验观察。

仍由原 receive_frame 读取/验证4B长度头、长度上限、body及原信封身份。保存原timeout并暂用
非阻塞recv；select每次使用原remaining_seconds，不刷新20ms。空就绪/would-block只续收当前
frame剩余字节，正字节推进并清零无进展计数，绝不重发stage/commit或复用失败材料。
每次等待前后、读取前后、收齐及恢复模式后重查原截止；迟到不返回结果供采用。
同一收齐调用连续8次无进展即 `LocalhostTransportError` / `no_progress_guard`，不谎称原截止已到。
原生TimeoutError/OSError按原传输错误类别停止，不无条件重试；EOF仍断连。finally恢复原timeout，
恢复异常单列；先前首错在恢复前锁定，不被恢复错误覆盖，也不由实验层关闭runtime拥有的通道。
模式/就绪/读取/观察/恢复成本全计原receive_ms和原周期，原设备/双提交/观察出口保护保持。

内部复用S13有界历史，容量按本次请求步数预分配，保留全部steps/events/cycles/party rows/null；
S13显式候选及默认4000门禁不改变。S15独立 `qpc_stage_receive_candidate` 元数据，最大1000，
`finite_sample_pass` 只对全部请求周期、数值/身份/资源/退出、完整历史/线程与新观察profile通过；
g399/g799等实际继续维护到达才记覆盖，未到不补测，旧资格flags始终false。

观察为 `qpc-stage-receive-v1`：Client原128 stage环/原首IO/GC不变，同一64KiB内增加总共16项
select/无进展/异常滚动事实及各一项首异常现象和首终止异常；P1/P2仍原stage-wait-light-v1。
非阻塞recv实际requested/observed timeout为0，select请求等待单列，绝不标成原S12 native-timeout语义。
全部时间整数QPC ns，仅公开身份/数量/时长/错误类别，不保存payload/份额/对象栈。
淘汰/编码省略/预算失败如实报告；不省略首错/原GC或新首异常来假装满足预算，不提高原
Client64KiB/合并192KiB。预算或恢复/观察故障拒绝有限PASS，控制首错与完整可靠前缀保持。
RV-003的确定控制/正常STOP边界与unknown归类沿用；失败轮未知不能变成“没有GC”。

仅软件检查、新head独立审查并释放、唯一预声明全文读回后，按另批D15一次执行：

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 1000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --qpc-stage-receive-candidate --output .tmp/issue120-s15-qpc-stage-receive-candidate.json
```

首次失败停，启动失败也消费，不补步/热身/20步/重跑/第二组/额外D14或baseline。
原D13/D14预算不恢复；一次满1000也仅有限样本，不证明S13内部根因或长期10000/完整路线/
真实认证三机/硬件达标，不据此推广或合并。D13/D14/D15及第6次原生定位预算均已消费，不可重跑。

## S17：正式QPC接收加固与唯一10000本机动态资格

第7次直接人工批准改变的是工程前置：不再等待S13历史故障复现。
S13内部原因仍未知，第6次真实根因闭环仍未完成；本节故障模型回归不称历史故障重放或内核修复证明。

正式`localhost_transport._receive_exact`遇到`_CycleDeadline`时，使用同一owner的
`_receive_qpc_exact`，S15和新资格观察也委托该实现，不保留第二套实验接收算法。
公共签名、长度头/body、信封身份、发送、控制/材料/双提交不改；旧float monotonic启动/保护路径保持原实现。
这是正式QPC接收行为的改变，不等于完整路线或认证部署已经验收。

保存原timeout、暂用非阻塞接收，在同一个绝对截止内推进当前字节游标；等待前后、读取前后、
收齐/转换和模式恢复后都查原截止。空就绪/would-block只续当前接收，不重发、不重建20ms；
正字节清零连续无进展，8次保护明确报错。真正TimeoutError/OSError/EOF/SSL错误仍立即失败，
恢复错误不覆盖先前首错，也不由传输helper关闭runtime拥有的通道。
TLS先尝试读取内部可推进数据，再按WantRead/WantWrite等待相应方向；pending为0也不能仅凭底层可读决定是否尝试。
保持已有TLS认证与关闭语义，不降级裸TCP。控制调用串行拥有通道，材料辅助线程只读其IPC；
不为任意外部并发/别名新增锁或线程。

`--qpc-dynamic-qualification`仅启用完整记录/验收门禁，接收仍是同一正式实现。
限定cycle/batch/fused/worker/light、10000步、400段/16库存/preload0/delay0、原本机insecure_tcp、
正常GC700/10/10/freeze0/debug0，与其它诊断候选互斥。没有Frida、原生桥接或辅助跟踪进程。
启动前核真实原schema布局：Client31159895B、各party3894625B、总38949145B；
仅此profile的Client上限32MiB，party16MiB/总48MiB、RSS256MiB、材料8MiB/16份保持。
原S13/S15仍原容量上限。只在内存捕获，退出卸载后完整展开/一次写盘，不筛慢步/失败/null。

新`canonical-qpc-receive-v1`公开观察覆盖Client所有QPC周期回复，仍为16项滚动/首异常及原stage/首IO/GC，
角色64KiB/合并192KiB不提高。完整10000路径应有120192次exact接收（12/步、24次维护各8）；
计数、恢复、首异常、预算/省略和全部历史/线程/数值/身份/材料/退出均须过门禁。
`local_dynamic_qualification_pass`只代表声明环境下本机动态资格；所有既有整体资格flags保持false，
三机TLS网络、完整路线/切换和真实设备资格另列。Client运行gen2及早empty实际覆盖独立报告，未出现不补造。

仅新SHA直接/完整检查及独立Review通过、目录释放、唯一预声明全文远端读回后才运行：

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 10000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --qpc-dynamic-qualification --output .tmp/issue120-s17-qpc-dynamic-qualification.json
```

这使用原未消费的一次10000额度，不新增定位/短测/性能次数；首失败停，启动失败也消费。
24次继续维护g399..g9599只有实际到达才确认，g9999终末STOP；不热身/短测/对照/额外D14/补跑。
任一失败仍未完成，不自动第8次源码返工、推广全线默认、合并/关闭或开始下一Issue。

后续第8次直接人工单次批准仅处理RV-004旧timeout/S10观察器兼容回归：
可恢复原生事件不占终止首错或其入口，后续普通I/O/GC继续；真正错误保留原入口、
部分字节与cause。此批准不增加试验次数；仍须新head软件检查和独立复审通过后，
才使用上面原未消费的一次10000预算。不自动第9次源码返工或新增定位/短测/重跑。

## S19：公开计划摘要减负与新授权单次资格

第9次直接人工单次批准仅减少`public_step_plan_sha256`的中间对象构造：标准JSON按需
投影公开dataclass字段，替代预先`asdict`递归深复制整棵计划；有限缓存仅含三种类型的字段名，
不缓存plan/round/摘要/能力，不删除任何资源或字段。原domain零字节、UTF-8、排序/分隔符、
Unicode与NaN拒绝及SHA256保持，worker/Client/peer仍独立调用同一个canonical实现。
非法循环仍按旧asdict的RecursionError拒绝，不改为JSON循环检查的另一异常类别。
消息/wire、来源与一次性能力、owner/锁/生命周期、数值/控制/期限/GC/内存预算均不改。

旧S17资格9807尝试/9806确认/1超期及全部原件保持，原预算已消费；本次另有一次最多10000
的新预算，不能拼接剩余193步。沿同一有效场景/worker/正常GC/20ms/400段/库存16/light，
软件检查及新head独立审查通过、目录释放和新SHA/源码/配置/环境唯一预声明全文读回后才可用：

```powershell
uv run secure-control benchmark --case cycle --mode batch --steps 10000 --delay-ms 0 --segment-steps 400 --material-slots 16 --preload-steps 0 --recording light --qpc-dynamic-qualification --output .tmp/issue120-s19-qpc-dynamic-qualification.json
```

新结果与独占log事前必须不存在；首次失败即停，启动失败也消费，不热身/短测/定位/对照/补跑。
完整周期/24维护/正常STOP/材料/状态/资源/历史与退出门禁不改；少分配可能只推迟gen2，
未覆盖Client运行期GC不等于消除停顿，退出GC不能充作控制内覆盖。原历史S13内部仍未知，
有限本机动态结果不授完整路线/真实TLS三机/Wi-Fi/硬件资格，不自动第10次源码续接或合并关闭。

## #166 共同基线的软件入口

运行入口为 `uv run python -m secure_control.experiments.performance_baseline`。
`prepare SPEC OUTPUT` 从公开配置身份、准确 source_head、八组两端绝对新路径和两机各自只读准备的 hosts 节点生成 run-0.json 到 run-7.json；仅准备，不启动控制。
L/F 顺序固定 L-F-F-L、F-L-L-F。两者共用 samples/2000、400步分段、16材料槽、20ms非实时相对节拍，不装 TailRecorder/GC 回调/stream map。F使用既有 NativeCapture 独立实例，只保存ETL/owner，不解析逐帧TCP。

每组批准格式为 schema=baseline-authorization-v1、purpose=capture-overhead-baseline-v1、source_head、plan_sha256（使用 native_tail_capture.plan_digest）、attempts=1、authorization_url（本Issue的新用户批准评论）。八组计划和逐端预算必须先经软件独审并由用户准确批准，不能复用历史control批准。
`run pair PLAN APPROVAL OUTPUT --expected-head SHA --config P1 --config P2` 在B执行；随后A执行 `run client PLAN APPROVAL OUTPUT --expected-head SHA --config CLIENT`。输出必须等于计划该端路径，账本在开始前永久扣额，不自动重试。

协调端在第一条运行命令前执行 `coordinate PLANS COORDINATION_OUTPUT`，保持窗口打开。每组提示后人工启动B/A，将两端manifest复制回协调机并输入路径；每组先领取再结算，失败/环境漂移/剩余额度不足120秒停止。批次一个本地monotonic计时，20分钟含协调等待与清理；人工输入阻塞不能硬中断用户等待，返回后如实标超额并拒绝下一组，不能宣传OS硬实时保证。
A总上限100秒、B业务监督110秒和清理至120秒；业务55秒、B等待45秒。F仍受各节点原采集期限与资源门禁约束。开始余量4GiB；软磁盘目标不等于OS硬配额。原生F当前仅Windows可用，Linux不得悄悄降级L，跨平台共同应用计时可单独运行L；混合系统F应另制定支持范围。

Client.json包含共同计时及控制终态；`metrics TIMING_REPORT OUTPUT` 只读生成>20ms比例、精确nearest-rank分位、连续预算超出、维护边界/随后两步、本步出口到下次采样间隔。Client.json内timing对象可作为TIMING_REPORT另存新文件。非实时真实deadline/lateness均null，不产生绝对节拍资格结论。数值正确性仍须结合原有控制契约与对照结果核验，单独计数一致不证明数值相等。

本入口的软件完成与性能收益是不同验收项；实际8组采集未运行前报告NOT RUN，不宣称采集扰动存在或优化已生效。背景负载对照需要另一份明确计划；不停止未知logger或安全软件。
