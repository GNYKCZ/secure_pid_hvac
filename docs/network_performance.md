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

Windows代理对尚未首次尝试的未来队首采用有界近到期检查：距due不超过500000ns时，只读QPC、非阻塞就绪和STOP，每次计划至多500000ns；就绪、due、资源检查点或本段上限到达即返回原外层。远期先检查即时事件，无事件才正sleep，最多`min(250000ns, remaining_to_due-500000ns, remaining_to_resource_check)`；不调用sleep(0)，不依赖正select timeout的亚毫秒精度。空FD不调用Windows select；空闲或仅有真实背压继续原阻塞等待，不忙重发已尝试块。非Windows沿原selector阻塞路径。

此策略依据文末第14次续接，替代旧“每次无就绪必正sleep”的策略。每遍仍先公平推进到期首次发送，每方向至多一个原块；真实selector返回时刻与主动检查episode区间分别记录。宿主抢占仍可能使实际检查超过计划上限，保留真实值和全部原误差，不裁剪或扣除CPU开销，原1ms门禁不变。不改系统计时器、优先级、生产角色或GC。

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

## 第13次人工续接：唯一一次compact-v2 N2候选验证

[本次设计与批准方向](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6231537918)将上一节零运行预算替换为**一次、最多1000次尝试的N2/candidate**；其他旧许可不恢复。
仅接通已有v2实验入口、预算和有限结果，M/R、控制算法、密码与材料内核、模型/seed、正常GC和正式默认不改。
入口修改产生的新head必须先完成软件检查并独立审查，通过后发布完整预声明并全文读回，才执行唯一native调用。

v2仅接受本次真实批准URL、N2/candidate、固定1000和原端口55121/55122/55123。
原账本`.tmp/issue120-network-budget.json`的全部五项规范摘要固定为
`ae524efc8bc7f8495ea511406a62410afdeb98a6761716ed2fe5610f5058aa2c`，最后一项必须是已失败的v1候选；此前5项/预留5000/实际2802保持。
只能追加第六项1000，实际累计不超过3802、预留合计6000；第六项已存在或在途、换URL/输出名/空账本/改历史/qualification均拒绝。
旧账本顶层6/15000是历史上限，不能作为本轮额外剩余额度。

新approval须精确绑定本次独立软件报告、新head/全部源码指纹、原环境/公开证书/端口、v2/candidate、全部五项摘要、一次/1000，eligible_for_candidate只允许本次、qualification_allowed=false。
manifest记录continuation_maximum_calls=1、continuation_maximum_attempts=1000和total_maximum_attempts=6000。
共享观察入口和实际循环都要求该manifest匹配当前源码以及原账本由当前进程锁定的未完成第六项，不能直接调用私有循环绕开占项。
Client及Party选择既有v2历史format_version=2以保留maintenance_advance；不会修改原M/R实现或把旧end/begin补零。

完整1000、20ms原全周期、原样本/材料/身份/退出/记录、TLS、1ms模型门禁及本次manifest全部成立才可network_sample_pass=true。
v2始终不授予network_dynamic_qualification_pass或任何长期资格；结果中的eligible_for_candidate/qualification_allowed均为false，说明本次调用退出后没有可用后续项。
只有本次绑定的有限candidate可能通过，纯软件v2数据或旧审核来源不能获得运行许可。

固定原5度初态、n4/m2/p1、ell32、原数值与认证模数、20ms、段400、库存16/preload0、持续worker/light、TLS和N2六方向250–500us/100Mbit/s/seed。
只读前置检查不消费调用；实际启动失败也消费，不重跑、热身、补足、A/B、额外探针或自动源码返工。
控制/通信/运行首失败即停；模型误差沿原退出汇总，未新增实时首模型异常停机机制，即使1000控制全按时也可能因模型错误判FAIL。
成功失败均发布完整可恢复原件、native日志及hash，并交Review只读核查来源、全分母、边界/首轮、模型和现有退出证据后停止。
新10000、qualification、后续优化、自动合并和关闭Issue继续禁止。

### 同次续接的过期测试证书例外

[限定证书设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6231758304)已由用户
[明确批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6231986263)，只解除证书到期阻挡，不新增调用或其他优化。
原四份证书和五项账本保留。入口软件经新head独立审查后，临运行前才使用原生成器向新空目录
`.tmp/issue120-compact-v2-certs`生成一日测试证书，不覆盖`.tmp/issue120-network-certs`，不公开或提交私钥。
不进行TLS试连或热身；离线检查原CA/角色身份、RSA-2048/SHA-256、SAN、双用途、签名关系及有效期，启动前至少剩一小时。

approval、manifest及第六项共同绑定`certificate_change_authorization_url`（本次6231986263批准）、
`previous_public_certificate_sha256`、`previous_conditions_sha256`、`public_certificate_sha256`、
`public_certificate_validity`（四份证书各自UTC not_before/not_after）及`certificate_change_reason=expired_test_certificates`。
原`authorization_url`仍为6231537918的一次调用许可，两者不得互换。
用当前ports/environment/seed和旧证书hash重算摘要，必须等于原五项逐项冻结摘要；只有证书hash可变。
新条件仅写第六项；共同候选校验同时约束外层、共享入口和实际循环，未经精确例外的相互一致新manifest/占项仍拒绝（RV-005）。
新文件hash、有效期或批准不符，夹带端口/环境/seed变化、已有第六项或任何qualification都不能启动。

新结果明确属于当前compact-v2源码加新证书条件，不能称为证书字节完全相同的配对A/B或排他的优化净收益。
失败启动同样消费唯一调用；结果完整发布并独立只读审计后停止，仍不恢复10000、不自动返工或合并。

## 第14次人工续接：有界等待与CPU保护，仅软件阶段

[本次设计及直接用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6235065606)仅允许修改实验relay等待及资源保护、对应软件测试和本文档。
原六项历史、预留6000/实际3802、旧新证书和全部原件保留；本次新增性能调用/周期预算均0，不恢复候选/10000，不为后续试验生成证书或运行许可。
上次e09807c的1000/1000完整按时、最大19.0414ms与79/16811读块模型误差超1ms仍归旧head/新证书条件，整体FAIL；新策略真实性能未知。

固定guard和连续检查计划上限各500000ns，CPU完整观测窗目标100000000ns；初始参数不按软件/实际结果自动调节。
CPU在外层约100ms资源检查点用QPC及process_time_ns采样，以真实相邻采样时刻作窗，不假定恰好100ms、不除以整机核数。
完整窗须满足`2*cpu_delta_ns <= wall_delta_ns`；超过单核50%即RelayCpuLimitError、保存首超限窗并关闭relay，model_valid=false，无旧策略回退或容差放宽。
该CPU包含relay服务观测区间的全部进程CPU，不从模型误差中扣除；短于100ms的退出尾窗单列且标complete_window=false，不能稀释已有超限完整窗。
[CPU起止澄清](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6235428785)：lifecycle累计量起于原started_qpc_ns，位于局部导入、selector/环/状态/模型准备之后、首个监听初始化之前；止于关闭资源后的最终QPC/CPU采样。
它包括该区间的监听初始化、建连、等待/转发、资源检查及关闭，不包括起点前准备、最终采样后的报告整理/JSON编码/pipe发送与关闭、进程最后退出；不涵盖整个OS进程或纯控制期CPU。
外层ended_qpc_ns不必等于CPU摘要结束点，不混用分母；lifecycle_complete=true仅表示服务区间最终采样完成，超限终窗也可完整观测而资格失败。
窗口及连续检查上限是进程获调度后的检查策略，不是OS硬配额或排他CPU隔离；实际被抢占时长仍完整记录。

报告追加`wait_policy.version=1`，含实际策略、guard/max_poll_episode/cpu_window纳秒参数、cpu_limit_percent=50、poll_episodes/poll_wall_ns/max_poll_wall_ns、
cpu_complete_windows、峰值/首超限窗（含实际起止和cpu/wall delta）、实际退出尾窗、生命周期起止/累计CPU与wall及lifecycle_complete。
失败取样的未知量不补零，cpu_sample_error_type明确；cleanup_error_type单列且不覆盖首个运行错误。时间/计数为整数ns，布尔状态另列。
wait_kinds只追加4=bounded_poll，原0–3及15列/256行数值环、9项首异常时序保持；selector事件携带真实返回时刻，主动到期不伪造可写事件。
新增摘要与旧记录仍受64KiB总预算约束；不缩环、删首异常或减累计。历史报告缺wait_policy表示未记录，不追认CPU通过。

软件检查包括可控时钟驱动真实relay的旧近到期正sleep晚醒反例、N1/N2/N3/空FD/背压、到期公平与真实就绪、STOP/排空、资源检查点、
CPU恰50%/超限/延长完整窗/不足尾窗/异常时钟、首错保护和满256行摘要边界，并沿用原短socket/TLS及协议功能夹具。
软件fixture不形成性能资格；完成新head必要软件验证、提交推送及独立审查后停止，若审查需要再次源码返工先报告，不自动循环。
