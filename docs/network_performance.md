# 安全动态平衡的本机网络模型实验

本入口仅用于#120获批的单机网络阶段：真实Client/P1/P2及既有供料worker连接软件倒立摆，原TLS1.3双向认证、安全计算和20 ms绝对周期保持。不能把本机127或自己的192.168地址、逐应用帧sleep、模型通过称作真实Wi-Fi/三机或实体设备验收。具体设计与授权见[固定网络闭环](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6208580212)。

## 固定条件与计时

| 场景 | 六方向额外传播等待 | 每方向速率 | 用途 |
|---|---|---|---|
| N0 | 无转发器，原TLS直连 | 无附加限制 | TLS本机基线 |
| N1 | 转发器，0 | 无附加限制 | 转发工具开销 |
| N2 | 0.25～0.50 ms | 100 Mbit/s | 唯一正常资格目标 |
| N3 | Client两链路同N2；peer两方向1.00～1.50 ms | 100 Mbit/s | 较差peer条件观测，不要求必然成功 |

固定公开jitter seed为12020261016，与密码随机材料完全分离。一个子进程转发三连接六方向的不透明TCP字节，角色仍端到端TLS，不在代理终止TLS、存私钥、解码或输出payload。每次读取最多4096B，不等待凑块；读取块不是TCP包。

读完块的QPC时间为a、长度为n、方向带宽为R：序列化完成时间为`tx=max(a,previous_tx)+ceil(8*n*1e9/R)`；不限速时为a。最早放行为`due=max(tx+传播等待,previous_due)`。保持FIFO、短写游标及半关闭；每方向排队最多1 MiB，总计6 MiB，队满停止读上游。角色bind在127.0.0.2、代理拨号host在127.0.0.1，各使用同三个固定端口；N0直接bind 127.0.0.1。身份DNS独立于地址，原SAN和TLS1.3核验不变。

真实socket就绪、FIFO积压和实际派发仍会增加开销。公开环记录入队/到期/首次尝试/就绪返回/推进/偏移及字节数，累计统计完整；超过1 ms而缺少既有FIFO积压或实际would-block解释的派发超出拒绝模型资格。select返回时刻是用户态观察，不宣称内核就绪时刻或独占CPU/GIL原因。所有实际时延仍计原20 ms，不给控制额外1 ms。公开环固定30 KiB、退出后编码总预算64 KiB，淘汰和首异常明确报告，不冒称保存全部块轨迹。

Windows代理存在尚未到期的队首时，先以`select(0)`检查即时就绪；无事件则使用严格正的`time.sleep(min(剩余等待, 250微秒))`阻塞让出CPU，醒后重新核对原QPC到期时间。Python3.11在Windows使用waitable timer实现正sleep；不忙等或调用`sleep(0)`，不依赖正select timeout的亚毫秒精度。空闲或仅有已到期但不可写的队列保留原阻塞等待，仍须到期且可写才发送。宿主抢占仍可能超期，原1 ms模型门禁不变；不改系统计时器、优先级、生产角色或GC。

原动态n4/m2/p1、ell32、逐行Trunc/旧state出力、数值证明、双提交及材料一次性不变；库存16、preload0、light、段400。正常GC700/10/10、freeze0/debug0；保留既有控制前清理，不在控制内主动collect或调整GC。原历史预算Client最多32 MiB、party各16 MiB/合计48 MiB（定位1000使用原较小布局），材料8 MiB及各进程256 MiB保护保持；离散RSS不等于连续峰值。转发进程同样受256 MiB保护。

## 软件前置与命令

当前旧网络闭环已在唯一 N2 recheck 失败后停止，旧 N3 和旧资格调用不得继续。
下列原流程说明保留用于解释历史记录；新的候选只能使用文末批准的人工续接。

先做模型独立整数oracle、FIFO/短写/背压/半关闭、原TLS身份与失败软件回归和仓库必要检查，提交/推送新草稿PR并实际交独立Review。pytest不含新1000/10000控制运行；普通socket/TLS功能fixture与正式性能调用分别记账。旧裸TCP资格入口和flags不放宽。

只在控制前，用既有fixture离线创建一次新证书（已有dev依赖，无生产模块导入tests）：

```powershell
uv run python -B tests/fixtures/prepare_local_lan_certs.py --output .tmp/issue120-network-certs
```

私钥仅留本地忽略目录，不提交或发布。运行前冻结实际源码SHA/指纹、四有效配置与初态/数值、OS/Python/OpenSSL/时钟、三个端口、公开证书指纹、模型/seed、完整命令/输出、总预算和停止规则，并发布全文读回预声明。端口必须先检查可用；以下固定端口只是本轮锁定后使用的命令形式。

独立审查放行文件由Work在完整读取/精确读回正式报告后准备，至少包括`head`、`source_sha256`、`software_pass=true`、`readback_exact=true`、当前Issue的`review_url`、`ports`、`environment`及四份`public_certificate_sha256`。它是本次既有审查事实的本地记录，不是独立认证机制或新增运行授权。生产模块不访问GitHub、不接触私钥内容来装配manifest。

```powershell
uv run secure-control benchmark --case cycle --network-profile N0 --network-phase discovery --network-certs .tmp/issue120-network-certs --network-ports 55121,55122,55123 --network-ledger .tmp/issue120-network-budget.json --network-approval .tmp/issue120-network-approval.json --output .tmp/issue120-network-N0.json
```

N1/N2/N3仅替换profile和独占输出名，按顺序各一次。不得传任意`--steps`、旧diagnostic/candidate/GC/QPC旗标或其他数学/通信对照；phase决定1000或10000，原资源固定。程序在启动角色前独占额度文件，持久占用调用项；启动失败也消费。已有输出不覆盖，崩溃在途项不自动重跑，所有预算文件与原件需保留。

## 最多6次、总计最多15000尝试

1. N0→N1→N2→N3各唯一1000上限，首失败停止该调用。N0/N1/N2意外失败暂停剩余场景；N3仅在当前候选N2完整成功后运行。
2. 只分析该次已有周期/分项/首错与代理公开时序；先在Issue写“证据→触发位置→拟改职责→不变约束→回归”。有真实软件问题才做一次最小性能修复，必要软件验证和独立复审后提交同一新PR，不另加诊断/热身/旁路调用。
3. 唯一recheck最多1000，与导致修复的场景/seed/条件相同，附`--network-repair-note`公开证据评论。若修复发生在N3之后，唯一复核用于N2确认目标不退化，N3原问题用软件反例验证，不加第7次。复核再次失败结束闭环；通过才继续未消费定位项，不重跑已消费项。
4. 当前SHA/源指纹下N2完整1000零超期、模型有效、必要软件检查和独立Review通过后，才允许唯一N2 qualification最多10000。资格放行还须`qualification_allowed=true`和当前N2原件的`n2_result_sha256`；端口/环境/证书/seed保持，原N2文件必须仍与被审摘要一致。
5. 最终10000的全周期、材料/状态连续、24维护、末双提交/正常STOP、完整历史/观察、资源/退出和模型全通过，才可`network_dynamic_qualification_pass=true`。discovery/recheck仅有限样本，旧全线/裸TCP资格flags保持false。最终失败不再自动修复或补剩余周期，未用额度不转移。

调用记录持久保存每次head、源指纹、预算、开始/结束、实际尝试、失败类别和原件SHA。报告`schema=network-cycle-v1`，保留所有cycles/steps/失败/null、六方向实际字节和公开时序、TLS身份事实、源/配置/环境及资源/退出。控制期间不写逐步大JSON，退出后独占导出一次；编码/写盘时间在CLI日志另记。成功失败都公开可恢复原件，不泄露秘密材料。

## 停止与解释

N0失败先看本机/TLS原路径；N1退化先辨工具开销；N2分析必要依赖、带宽/排队和角色已可用后的处理；N3只是更差peer条件。嵌套区间不能相加，GC/调度重叠不作唯一网络因果。没有可证实的软件问题不制造修复；若只是网络依赖下界或工具/宿主不能执行模型，报告可复核阻挡。需改协议/ACK/屏障、数学/安全/生产架构时，交具体设计决策，不擅改主线。

运行期gen2专项、完整安全起摆/阶段切换、真实TLS三机/Wi-Fi及硬件仍独立未验收。旧失败/S5/S13根因未知和全部旧证据保留，不重标新SHA。新网络PR不自动合并，#120不关闭，闭环完成或触发停止条件后结束，不自动扩展下一支线。

## 已批准的动态紧凑候选续接

本候选依据[减少分发与多轮交互设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6212118129)，
用户直接批准登记为[本次实施与两次验证授权](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6212453192)。
三个角色必须显式协商 `control-dynamic-compact-v1`；默认 `control-batch-v1` 与有限预送格式保持原语义，混用直接拒绝。

动态材料复用预送的定宽无符号大端 residue 编码，再用规范 base64 放入原 JSON 信封和4字节长度帧。
宽度为 `ceil(q.bit_length()/8)`，严格检查 `0 <= z < q`，禁止 bool、浮点、截断和隐式取模。
每方材料按原计划的全部 `(a,b,c)`、再全部状态行 `(r,r_prime)` 排列。
当前 n4/m2/p1、256位模数是98个整数、3136字节、4184个 base64 字节；完整 `online_stage` 应用帧在软件夹具中检查不超过8 KiB。
公开计划与资源标识由接收方认证布局、session、round、全局步重新派生，再核对原 `public_step_plan_sha256`，交给原 recovery 与生命周期 owner。
worker 规格、包头、通道来源和原始能力均绑定编码 profile，保留哈希、精确长度、额度、槽与内存保护。

Client 预先构造、编码并检查两方完整 `online_stage` 请求，然后两方均发送后才接收。
Party 安装当轮材料后直接调用同一个 `stage_protocol3_batch`，返回原暂存结果；没有新协调器算法或有限预送缓存。
普通轮由 Client 12帧加 peer 7帧的19帧，变为 Client 8帧加 peer 7帧的15帧；分段与停止消息另计。
peer 在同一连接、同一 owner 线程内非阻塞推进一发一收，支持短读写、TLS WANT 换向和原绝对截止，只有无进展才等待就绪，并恢复 socket timeout。
依旧保留乘法遮蔽、乘法完成屏障、P2单向截断、状态完成屏障四个依赖阶段。
观察器将双向 helper 的真实发送帧和4字节帧头纳入计数；双向 native 记录的 confirmed 字节是两方向累计，不能解释为某个单向帧的确认游标。
这些结构减少不代表固定时延收益，也不代表20 ms已达标。

本次先完成必要软件检查、提交同一 PR #124，并实际交独立 Review。若 Review 确认需要额外源码修复，停止并报告，不自动增加一次返工。
软件放行记录新增 `wire_profile`、用户登记评论 `authorization_url`，以及原已停止调用列表的规范摘要 `closed_history_sha256`。
它们和当前 head、源指纹及独立报告绑定；仍只是已核实事实的本地记录，不是新认证或授权机制。
不得创建空账本或篡改四项旧记录；只在同一个 `issue120-network-budget.json` 后追加新授权的两项状态。

1. 唯一 N2 `candidate`，最多1000次尝试；失败或启动失败均停止，禁止重跑、热身、短测或补跑。
2. 仅第一项完整通过、模型/证据/资源均满足，并经独立实际结果审查后，同一完整 head/源指纹才可唯一 N2 `qualification`，最多10000次尝试。不能在两项之间修改源码。

网络命令在原显式参数外，须增加 `--network-wire-profile control-dynamic-compact-v1` 和 `--network-authorization`，后者填写上面的真实批准登记 URL；首项使用 `--network-phase candidate`。
资格项还需原有 `qualification_allowed=true` 和第一项真实原件的 `n2_result_sha256`。
全部原20 ms/QPC、正常GC、库存16、preload0、段400、light、TLS、N2模型/seed、设备与账务计时条件保持。
新续接最多2次/11000次尝试，旧四次保留；总账最多6次占项、15000次预留，不复活旧闭环未用配额。

## 第12次人工续接：compact-v2 软件实施，性能预算为零

当前决定以[新设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6218014238)和
[用户批准登记](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6218076087)为准。
上节 v1 的唯一候选已实际失败：800次尝试、799个完整周期按时，step799维护后超期；模拟器有48次未解释误差超过1 ms。
原10000资格没有启动，不能恢复。既有账本5项、预留5000、实际2802保留；失败调用剩余次数不退回。
本轮只实施和独立审查软件，新增性能调用/周期预算均为0，不执行候选、资格、热身、短测、微基准或GC变体。

显式 `control-dynamic-compact-v2` 复用 v1 数值编码、融合在线阶段及 peer 双向交换。
Client/P1/P2 hello、在线/peer载荷与worker编码来源必须精确匹配该版本，无自动降级；正式默认仍是原批量模式，v1行为保留。
仅同epoch动态分段模式可选择v2，不能与预送、完整v3或阶段切换混用。
协议只在已双提交并完成设备确认的满段边界，将原continue End和下一Begin合成 `segment_advance`：

- Party完整校验End、Begin与本地前缀后，快照旧回执，再切换公开分段账本并回复。
- Client先发送双方完整预检的请求，再逐方核对旧回执的role/session/提交/资源计数和下一Begin；一个复合操作只消耗一个Client到Party序号。
- 旧段记录绑定旧hello、旧段步骤和两份旧回执；段seal、来源复核、release和原截止检查通过后，才本地激活下一段，不再发送begin。
- 单方确认、断连、超时或本地检查失败均不重试、不回滚已提交状态、不复用材料、不再输入；保留已验证回执及最后完整密封事实，异常关闭。
- 发送前固定stop走原停止。continue决定发出后不改写；双确认和本地检查完成后，可在下一段零步stop，不额外执行控制。

普通轮仍15应用帧；满段额外维护由8帧降至4帧，边界合计23→19。应用帧不是TCP包，不据此承诺固定RTT收益。
`maintenance_advance`记录实际执行的复合维护，未执行的旧end/begin分项缺省，不用0代替；嵌套区间不得相加。
固定历史仅显式选择v2时增加该字段并报告format_version=2；旧历史字段、固定内存布局与预算校验保持。
所有维护仍属于原400步边界的同一20 ms周期，不能挪到下一输入或放宽截止。

模拟器每遍以新鲜时钟先尝试已到期且从未尝试过的队头，六方向轮转，每方向至多一个原4096B读块；随后仍服务STOP、读事件、100 ms RSS采样及等待。
短写或would-block后仅依据真实可写事件推进；未来due不会提前发送。socket方向映射建连时固定。
Windows内存API的结构和签名只初始化一次，每次采样仍查询OS；缺失或超过256 MiB继续失败。

转发记录 `ring_version=2` 保留原15列；`writable_return_ns=-1`表示直接首次发送没有selector可写事件，旧无版本记录沿用原语义，不改写旧原件。
首异常另有固定整数快照：最近wait类型（0无、1 selector、2 release_wait、3 stop_wait）、wait进入/返回/计划唤醒、loop开始、最近RSS起止和本次send起止。
数值环仍256项/30 KiB，退出后公开JSON总预算64 KiB，保留首异常和淘汰计数；不保存TLS或秘密材料内容，不增加控制期写盘。
首次误差仍从原eligible计至send返回，迟醒和2 ms慢send仍拒绝模型资格；后续真实背压另列，原模型、seed、FIFO、带宽及1 ms门限不变。

软件验证包含短小真实TLS协议夹具、跨两个400步边界的精确整数/资源轨迹、错误身份/部分确认/停止竞争/本地失败，以及可控时钟下的模拟器反例。
短TLS夹具可使用较小段容量验证重复维护结构，不形成设备确认或20 ms性能证据；正式配置仍为400。
新profile只可解析软件证据，现有性能入口和额度函数不为它开放，报告组装也不能使它获得性能资格。
软件通过及独立审查后停止；发现新缺陷先报告用户，不自动增加返工。新版本20 ms性能与模型验收仍未知，PR继续Draft且不合并。
