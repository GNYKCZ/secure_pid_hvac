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

## 第15次人工续接：有条件的A/B/C性能闭环

[本次设计与直接用户要求](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6235872603)
允许必要许可接线，以及A证据支持时至多一项局部patch。自动返工仍3/3，前14次人工续接保留。
本轮交付要求有效N2下10000/10000完整按时、0失败/0超期，完整周期max≤18 ms且p99≤16 ms。
这比原20 ms有限网络资格更严格；网络资格成立但18/16不足仍属本轮目标未完成。软件检查不代表实测进步。

原唯一账本保留六项规范摘要`da18c50ed0e175257b7c058943dd2ff3c470669573672179c16d1e47b59e18c4`，
原六项预留6000/实际3802不改。新授权仅新增≤3调用/≤12000尝试，有效累计上限9调用/18000预留；旧6/15000不能当作剩余额度。

| 阶段 | 条件 | 唯一调用上限 |
|---|---|---:|
| A / call7 | 入口新head独立软件审查通过，保持b660等待/控制行为 | 1000 |
| B / call8（可省略） | A不足且明确定位一项获准局部修复；新head独立软件审查通过 | 1000 |
| C / call9，省略B则call8 | 前置1000原件独立审计且完整门禁及18/16通过；严格同head/指纹/条件 | 10000 |

失败启动占项、未用尝试作废；没有重复A/B/C、第四次、热身、短测、诊断分支或GC变体。跳过B不转移其额度。
共享入口、实际循环与外层复用同一许可判定，绑定六项前缀、阶段、当前进程账本锁及在途项、全部源码指纹、条件、审查URL和前置原件hash。
C启动前从前置原件重算完整门禁及全部周期的max/p99，不信预填pass；B失败或不足不进入C，C失败即停止。
若A证据不能支持具体局部修复，则报告差距并交Design分析，不凭猜测调参。不得放宽1 ms模型误差、单核50% CPU或500 µs guard/poll上限。

原v2/三角色TLS1.3、身份、20 ms绝对截止、400步分段、16槽/preload0、worker/light、正常GC及N2六方向/seed保持。
原数学、材料一次性消费、双提交/设备确认和全部维护计时不变。10000的v2历史复用现有上限：Client31,339,913B，
每Party3,894,625B，合计39,129,163B，分别低于32/16/48 MiB；全部行、失败null及maintenance_advance保留。
网络有限样本另核已记录CPU完整窗/峰值/退出尾窗及服务区间完成状态；历史缺CPU事实不追认通过。
`network_progress_goal_pass`独立于`network_dynamic_qualification_pass`，前者还要求18/16；两者均不授予真实三机/Wi-Fi/硬件资格。

A前优先复用`.tmp/issue120-compact-v2-certs`；仅其余期不足一小时，才准原生成器在新空目录
`.tmp/issue120-network-closure-certs`准备一次同身份/规格证书。旧证书保留，离线核四份公开证书/链/有效期与指纹，不做试连。
manifest记录certificate_directory、public_certificate_validity、旧/新公开指纹与旧conditions；换证原因固定为insufficient_validity_before_A。
A/B/C冻结同一套条件/证书，每次启动仍需至少一小时余期；A后不足则阻挡，不再次换证。与e098旧样本只能作历史比较。

先软件验证、提交推送与独立审查，再发布并全文读回精确预声明，才能执行A。每次实际运行保存全量原件、native日志/退出码、hash及独立数据审计。
本节仅登记许可与验收方法，尚未产生本轮性能成绩；不自动合并、关闭Issue或开始下一Issue。

## 第16次人工单次候选：Windows统一事件等待

[具体设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6245910420)和
[直接用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6245981263)
允许现有relay进程内的一个新等待候选。原自动3/3、前15次人工历史保留，不授权下一次自动源码返工。
旧A仅211尝试/210完整确认，因CPU窗62.4962%保护停止且5/3610块模型超1ms，仍为FAIL；
210前缀max13.9258/p9911.768198ms不能当作有效1000/10000成绩，完整原件与版本1事实保持。

新私有`_network_wait_win32.py`只封装标准库ctypes的Win32 ABI、socket事件状态和一个可复用高精度timer。
显式选择`win32-event-wait-v1`后，由原relay调用WSAEventSelect/WSAEnumNetworkEvents及WaitForMultipleObjects，
统一等待真实网络通知或最近due/原100ms资源检查期限；不增加线程、进程、依赖、驱动、优先级、绑核或管理员操作。
未显式选择的旧入口/默认策略不变。原调用者继续拥有FIFO、due-first轮转/每方向单块、收发、STOP/5s排空和CPU/RSS保护。

QPC绝对期限先扣当前QPC，再向上取整为负相对100ns的一次性timer期限，无APC/周期/合并容差；
timer可唤醒但不等于socket可写，到期后仍由原QPC判是否可发，不提前发送。能力/系统调用失败明确退出，不降级sleep/忙等。
每次返回有界收集全部当前通知，避免较小句柄索引偏置。STOP仍由原循环检查，计划最晚100ms资源唤醒；实际迟醒照实计入，不承诺OS硬实时。
WSA网络事件用原子枚举消费/复位，不能任意ResetEvent丢通知。FD_READ在recv前消费，队列暂停/恢复保留状态；FD_CLOSE仍先读完缓冲再EOF。
FD_CONNECT错误交原重拨逻辑，accept继承listener事件后先解绑；socket对象/FD复用不能认领旧事件。

FD_WRITE为边沿，收到后保留可写状态；只有实际would-block清除，等待下一次真实FD_WRITE。
首次到期发送消费此前已使用的可写通知，不将旧时刻遗留给后续短写。原生等待初始化失败也进入结构化首错报告，wait_policy=null表示尚未建立策略，不伪填旧策略或继续运行。
正数短写按原公平上限继续；缓存状态不伪造新的可写返回QPC。为保留完整派发/处理时间，短写继续从上次send实际完成计到下次send完成；
真正背压恢复从真实FD_WRITE返回计时，首次发送仍从原eligible计时。全部实际迟延仍受1ms门禁。
数值环仍15列/256项/30KiB，native分支`ring_version=3`且`writable_return_ns=-1`表示没有新可写通知（含已验证正短写的缓存状态）；旧1/2版本不改写。
等待类型新增5=native_network、6=native_timer，原0–4保留；首异常仍9项实际时序，摘要总64KiB上限不变。

新报告`wait_policy.version=2`、strategy严格固定上述名称、active_poll=false、guard_ns=null、max_poll_episode_ns=0，
原poll计数/墙钟/峰值均0。固定追加native_wait_calls、network_notifications、handle_high_water、handles_open、最后等待实际起止/目标QPC；
每socket一个独占事件和每relay一个timer，句柄总数≤16，非继承/无名称，无每读块句柄；部分失败与退出继续关闭全部资源，首错不被清理错覆盖。
CPU起止仍在等待器/局部准备后、首监听初始化前至关闭资源后的最终采样；包括该服务区间的初始化/转发/等待/关闭，
不包括此前ABI/适配器准备或之后报告编码/IPC/最终进程退出，不称全OS或纯控制CPU。约100ms实际完整窗单核50%、峰/首超限/退出尾窗不移动、不平均、不豁免。
新许可只接受版本2固定策略/零poll/句柄清理事实，不能靠任意strategy绕过；旧A仍要求其原版本1事实。

许可在原owner中绑定本设计/批准URL、包含适配器的全部来源及固定七项规范摘要
`cc6b6a46b009fbebc32700e32ac65e348f3f10c474e6f219f2a39ecb0785c3b4`。
旧七项对象/raw/native不变；固定A后禁止回退旧B许可或重跑A。仅复用原call8 B≤1000；B完整有效N2且18/16通过、独立原件审计后，严格同源/同条件call9 C≤10000。
剩余条件额度2调用/11000，不新增次数；A未用789作废，历史预留7000/实际4013保持至B真正启动。
原正式默认、控制/数学/材料/TLS、15帧及跨段额外4帧、双提交/设备确认、20ms/18-16、正常GC及全部资源门禁均不变。

仅B前旧证余期不足1小时，准在新独立`.tmp/issue120-network-closure-certs`一次准备原同规格证书，
绑定certificate_change_authorization_url=本次6245981263、reason=insufficient_validity_before_B、新旧公开hash/有效期及conditions差异；旧证保留。
不能在旧证充分有效时换证搜索条件，B/C固定同一套，C再过期则停。不是新A或配对A/B收益证明。

必要软件/原生功能检查和独立软件审查后才预声明并执行唯一B。原生功能夹具只验证ABI、字节/通知/背压/半关/句柄与失败，
没有plant/20ms控制循环、时延分位、额外性能或参数搜索。模拟迟醒仍应模型FAIL，timer不保证调度准时。
B或C失败停止本候选，不添加探针/变体/自动返工或自行换平台；只有完整有效C/10000零失败零超期且18/16通过才达成本轮目标。

## 第19次限定续接：修复后复验与条件资格

[设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6251910122)与
[直接用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6251961861)
仅新增两个阶段：`continuation_stage=repair_recheck`（call9，candidate，最多1000周期一次）和
`repair_qualification`（call10，qualification，最多10000周期一次）。R1完整通过全部原门禁及
max≤18ms/p99≤16ms，原件经独立审计且同源/同条件后才有Q1。任一步失败或证据不足停止，不补跑/热身/追加探针或自动返工。
旧A/B剩余步数作废、旧C未解锁；新的上限不是复活旧C。原八次8000预留/4014实际保持，新增最多2次/11000，累计封顶10次/19000。

原RunBudget仍是唯一预算owner；同一正式CLI/共享/实际入口都核对本次批准、完整head/来源、固定八项canonical与native历史、当前native START和在途占项。
原八项摘要分别为`5e28dad8b899e1653f0c165ef5661027ac1f9d9fd684bc2ec2ac64a3ef3dc99c`和
`f429510fb22e70ea865b10dd084581e56199bf087cc81c44ed071ed7ebc6e120`；前缀对象/原件不改，只有真正追加后账本整体hash自然改变。
native记录工具在发起CLI前持久化START并保留原生exit，不能另行放行；CLI启动失败也消费，native/canonical不齐或有在途即阻断，不能删除记录重试。
新manifest加入`continuation_design_url`、`closed_native_history_sha256`、`native_ledger_path`，authorization必须是本批批准URL，不能填旧批准或设计URL。
准备工具只负责冻结/公开/核对事实，不得猴子补丁或另开账本绕过入口。

优先复用`.tmp/issue120-network-closure-certs`；每次启动离线核验至少一小时余期。仅R1前原证不足时，按批准在此前不存在的
`.tmp/issue120-network-repair-certs`一次生成同身份RSA2048/SHA256/25h证书，记录新旧公开hash、有效期、条件和
`certificate_change_reason=insufficient_validity_before_R1`、`certificate_change_authorization_url=本批批准`。
旧证仍足够有效不得换，Q1同套且不得再换；私钥/旧证均保留，不试连搜索条件。

本批不改relay候选、控制算法、协议、材料/worker、正常GC、正式默认或N2模型。新授权严格选择原native版本2策略并执行
原50%实际CPU窗/零poll/句柄/1ms模型/完整周期和18–16门禁，缺失wait返回仍拒绝。
入口适配的新head须相关与全量软件检查、独立软件审查、完整预声明及全文读回后才运行。R1/Q1各自全部原件/命令/native退出、
材料/状态/资源/清理和后置退出观察均保存并独立核验；失败/null/慢步不删、不将成功前缀冒作完整样本。
软件通过、R1有限样本、Q1本机N2资格分别记录；不据此宣布真实Wi-Fi/设备/长期硬实时、gen2专项或完整路线通过，不自动合并或关闭Issue。

## compact-v3 局部暂存与 T1/T2/T3 有限比较

[本轮设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6284803981)及
[追加用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6284903029)
允许显式11帧候选的软件实施、首次独审、一次必要返工，以及软件/独审通过后的最多三次比较。
PR #125 非前置且不纳入此轮；不更改默认配置、数学、20ms周期、精度、材料、GC或网络模型。

`control-dynamic-compact-v3` 仅用于需要聚合行 Trunc 的动态分段 worker 实验，拒绝静态、
无截断、preload/full入口和混合版本。正常 peer 为 product×2、truncation×1，取消两道
peer 完成屏障；Client 验证两份局部回执及输出后授权提交，双方 ACK 保留。
普通完整轮11应用帧，满段 advance 连同维护15帧；v2仍为15/19帧。

原 `RunBudget` 增加本批 `comparison_stage`，保留已封闭九项 canonical 摘要
`08805f3aa8e0149771f05d7519c51f8801345e9c47f24a86d9848eb447a14852` 与 native 摘要
`61dcefa48b1314ca1d86e9ab039dc3f214ab0c746ced453090557d26c3b079be`。
九项9000预留/4209实际保持；新增call10–12各最多1000，累计最大12次/12000预留。
旧R1/Q1判断和历史对象不改；旧授权不接受新阶段，新批准也不能解锁旧资格。

T1=N0/TLS直连/v2，T2=N0/TLS直连/v3，T3=N2/v3，均固定candidate/1000。
T1完整1000、零失败零超期及全部原门禁通过才允许T2；两次必须同head/来源/条件，使用
各自新鲜材料。T2完整周期p50≤T1的90%、p99≤T1且max≤20ms，两份精确原件经独立审计
才允许T3。T3保留原六向250–500µs/100Mbit/s、seed、原生事件等待、单核50%实际100ms窗、
1ms模型误差、材料与角色内存保护；完整1000零失败零超期，余量目标p99≤16ms/max≤18ms。
统计包含首轮及400/800维护，帧计数来自三角色实际transport。正常结束、材料清退和TLS
身份也必须通过；不足不能只用平均值或成功前缀掩盖。

每次native START（含准备/启动失败）消费一次；首次失败立即停，剩余额度不补发。
任何源码变化使同源比较失效，停止剩余阶段；没有热身、探针、重跑或10000资格。
T2墙钟收益不足单独报告，不冒充控制错误。一次Review修复也不返还性能额度。
当前进程锁、在途占项、原件hash、来源及前件门禁在CLI/共享/实际循环都核验。

仅T1前旧证余期不足时，在此前不存在的`.tmp/issue120-stage-authorized-certs`一次生成
原同身份/SAN/RSA2048/SHA256/25h测试证书，记录旧/新公开指纹、有效期、条件和批准URL；
旧证及私钥不覆盖。三阶段同套且每次余期至少一小时，中途失败不自动换证。
本节登记候选及受限验证流程，不代表已产生有效性能成绩或整个Issue #120验收通过。

## PR #126 局部摘要优化续接：U1/U2

[新设计及直接用户“允许按顺序”登记](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6289274852)
仅允许本轮 owner 摘要复用和期望对象减负、软件/独审，以及新同head的两次N0直连对照。
原T1/T2已完成且净收益失败，T2原生exit5保留；T3继续封闭。

新增协议授权路径摘要目标为Client每轮最多1次、每Party最多1次，其他LAN/peer已有摘要
单列。仅缓存经核实深层不可变且为同一对象的本地公开plan；不缓存消息检查成功或动态状态，
不信任收到的摘要。wire、11/15帧、原数学、双ACK、20ms及phase时点均不改。

现有预算owner仅接受本次设计/批准URL、`comparison_stage=U1/U2`与固定原11项摘要：
canonical `b9a468b68413d80e2c1daaa4ac9ce6700d555bb9c7717fee00563c951909d2d7`，native
`61f4826e58ff45d91417fb72024dd8c43f5a6d51bed7d7829650306f62705cb7`。
原11次/11000预留/6209实际不变；仅call12/U1=N0/v2和call13/U2=N0/v3，各一次最多1000，
累计最多13次/13000预留/8209实际。U1须新已审head/来源，不能重跑旧head；U1完整成功且
正常原生退出才U2，同head/同条件。原失败不篡改，不要求把旧T2退出改成0。

正常GC、原启动清理、worker16/8MiB、light/preload0、段400和TLS保持。必须复用现有
同套证书/条件，不含再次换证授权；余期不足一小时则报告停止，不启动注定失败调用。
完整来源/真实命令和条件预声明在START前发布并全文读回。START含准备失败均消耗，
首败停，无重试/热身/探针/额外10000；U2无论结果都停止，不继续N2或借用旧T3。

保持原收益门槛：两组各1000完整、0失败/null/超期，首步及399/799维护全部计入；
U2全周期p50≤新U1的90%、p99≤U1、max≤20ms。复用整数端点与原门禁，分项中位数不求和，
不拿旧head基线正式配对。完整raw/native/hash/条件/账本与退出结果再次实际交Review审计；
软件无变更不重复全量。这里尚未产生U1/U2实测结果，不宣称收益或Issue完成，不自动合并。

## PR #126 固定控制实现的唯一 N2 续接：V1

[新执行设计与用户批准登记](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6307818461)
仅允许一次V1=N2/candidate/compact-v3，最多1000次尝试；不借用旧T3或已用尽U批次。
[U1/U2独立结果审计](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6291716161)
确认同head各1000零超期和11.00%有限中位收益，旧失败及退出5仍保持。

控制基线为`44472725f908ef5c8a9a610a689b037bb38ee36f`。本轮只在既有实验预算/证据owner
增加V1许可，必要CLI退出路由、测试和本节文档；控制循环、protocol/crypto、worker、codec、
transport、relay/native等待、GC、动态配置和依赖不变。实际运行记录新入口head，不把旧N0
成绩重标为新网络成绩。来源核验逐文件对照旧U2，只有实验入口/退出路由可变化。

原13项canonical/native规范摘要固定为
`32bda5b0e9b350164dcb8f972edc02f2724fe3b7e167222b50c9f12f807e6a22` /
`ba432f89d849b8a3cbcb39b20943e6b3653df83046be0d3a7d1d655c042d41a8`。
只追加call14、batch1/1000，累计最多14调用/14000预留/9209实际。两个原账本、原独占锁、
真实native START和当前在途占项继续核验；正式START含准备失败均消费，不删缺项或补跑。
V1绑定精确新批准、旧控制head、独立审计与两份固定raw摘要，重新读取完整原件并按原样本
门禁及10%收益重算。CLI/共享/实际循环使用同一许可；第15次、第二V1、旧T/U、N0/N3和
qualification均拒绝。新软件检查及独立软件审查必须先完成，不重复N0对照。

原六方向250–500微秒/100Mbit/s读取块FIFO模型、seed12020261016、4096字节读取上限、
原N2拓扑、TLS身份、win32-event-wait-v1/version2、100ms实际CPU窗单核50%、1ms无法解释
转发误差、每方向1MiB及原退出门禁保持。不能用N0占位或仅凭共同条件hash判定实际模型。
复用现有stage-authorized-certs四公开证书，每次正式START前只读核至少一小时余期；
本轮不含生成或替换证书许可。余期不足或端口/来源等预检不满足就报告停止，不试连探针。

结果分别报告原模型有效性、完整1000周期零失败/null/20ms超期样本，以及p99≤16ms、
max≤18ms的余量目标。18ms不是新的控制deadline。首轮、399/799维护与末轮全部计入；
普通11帧、完整维护15帧、双ACK/材料/STOP/TLS/资源及退出门禁不放宽。模型无效时不能
判断网络性能通过，保留实际控制事实；样本按时但余量不足也分开报告，原生CLI返回失败。

完整raw、真实命令/START/原生exit、全部角色与relay记录及后置退出观察可恢复发布，再
实际交Review独立结果审计。成功或失败都在此次V1后停止，不追加热身、探针、重跑、
10000、网络/控制优化或换证。这里只登记新许可，不代表已运行、真实多机/Wi-Fi、无证书
演示、gen2专项、长期资格或整个Issue验收通过；不自动合并或关闭Issue。

## 中继等待取证与有限修复：W1 / W2

[本批设计与用户同意](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6308806798)
允许先观察原等待算法、唯一W1取证、独立核原因；仅证据支持相对期限准备、当前owner缓冲/
句柄准备或确认的重复派发工作时，实施一个局部修复、软件独审，再唯一W2复核。
主要归属系统Ready→Running、未知内核等待、未复现或证据不足时停止，W2不使用。
控制、密码、材料、模型/阈值、正常GC及系统电源/优先级/亲和性/全局timer resolution保持。

W1在现有NativeWait内显式启用8次最近等待整数环；记录PID/native TID/wait ID、原QPC目标、
相对100ns值、timer设置前后、句柄准备完、等待调用前/返回后、事件收集结束、返回relay。
时点是Python可观察FFI边界，不是内核timer signal。未执行/异常字段为-1，不继承旧值。
首超差保存原256读取块环、原首异常及固定等待快照；仅目标与时序相符才关联wait ID，
否则明确unassociated。仍保持64KiB公开上限，超预算显式失败。默认无细粒度观察，W2关闭。

W1/W2显式首模型失败停止：实际send/would-block的字节/计数/首错先记录，再走原关闭和
失败报告，不声称撤回已发送内容，不修改due/eligible或扣掉系统开销。TLS启动期异常同样
消费本次。控制角色沿原断连/未知提交保护停止，清理不盖首错；W1不足1000是诊断结果，
W2不足1000是验收失败，均不补跑。

W1还在canonical预留后、控制前启动本机WPR任务具名实例Issue120W1，一次32MiB内存环，
只含ProcessThread/CSwitch/ReadyThread/ThreadPriority/CpuConfig/Interrupt/DPC，无stack、
采样或网络载荷。先只读验证profile/工具/无他人会话，finally只停止本任务已启动实例并保存
本地ETL；外层native所有者限制总采集90秒。WPR失败/丢事件/解码或时钟映射不可靠时，
不能给确定根因或重复采集。原ETL留本地，公开仅relay目标线程与必要匿名化调度片段、
原件hash和映射方法；不上传其他应用的名称/命令行或完整ETL。离线tracerpt解码可重做。

现有两账本仅追加call15=W1/call16=W2，各最多1000，batch2/2000，累计最大16/16000预留/
11209实际。前14项canonical/native固定为
`55b2fda1991b4ba65cd67fb7ec87addc0b865bb8f14289b10c71eb49cc403902` /
`08374e2f98cc0381ff855bb5b3ac0dd3a03aa0a46508b366efd6b898fe686b93`，旧exit5保留。
W2不是root_cause布尔解锁：必须有精确W1 raw/native、新修复head、原因区间及系统证据摘要、
独立原因审计和修复报告。旧许可/第17次/第二W1/10000拒绝。每阶段相关及全量软件检查、
独审与完整精确预声明先于运行。正式START后准备失败亦消费，缺项不修账返额。

优先复用原证；仅W1前不足原≥1h余期时，可按原生成器在新的ignored目录一次生成同规格
同身份链，保留旧公开指纹/有效期/条件及本批理由；W1/W2同链，不允许中途第二次签发。
原N2六向250–500µs/100Mbit/s、seed、20ms与16/18余量、4096B/1MiB、CPU实际100ms窗50%、
句柄≤16、普通11/维护15应用帧及原TLS/资源/退出门禁不变。W1不是配对净收益基线，W2
没有WPR或细粒度观察。任何路径均实际交Review审计原件后停止，不自动合并或关闭Issue。

RV-009清理约束：start前在确认全局及本任务具名实例均未记录后，先持久化独占claim；
start命令超时也保留归属。stop失败/超时与已停止但保存失败分别记录，只核本任务具名状态，
必要时一次具名cancel并再次确认停止；确认前不释放归属，不覆盖首个start/stop/控制错误。
外层native所有者对正常0、失败5、异常和超时均在finally核claim并有界收尾，不仅等待超时才
处理。无claim或claim不符不碰任何会话；无法确认停止时保留未释放事实、阻断后续，不重采。
原CLI70秒、只清理任务进程树≤5秒，剩余时限内具名status≤3秒/cancel≤5秒/确认≤3秒，
总采集上限90秒不扩大。此处cancel是终结已失败的本次记录，不是第二次采集或重跑。

## SC完整周期两版本比较（N0/TLS）

[SC-E2E设计与用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/120#issuecomment-6333274397)
只允许SC-A/SC-B各一次最多1000周期。A从main767c2a14只加共同实验支持H，B从已审
SC提交2b1c40a4加相同H；两完整版本只允许secret_sharing.py四行及其测试不同。
新增来源明确包含secret_sharing.py，旧记录的来源键/摘要不回填。SC manifest绑定两head、
两source映射和实际独审报告，两版本共同H及其余生产文件通过Git内容核验；所有角色和
worker在同一冻结checkout上正常spawn，不使用进程内算法替换。

原15项budget/native摘要分别固定为
e1e6ebdc02516f43624ec5c82a3de1db30a5873a6ea686b6e65843a2866fec56 /
b0f927d5e368a97a8e16b3de4d9eb7898ad6e3edb413f56a40ab020876b43a0d。
SC独立scope只追加call16/17，总占项上限17000，不挪旧PS/W2；锁、START、准备失败
消费及唯一原件保持。A须全部1000完整零失败/超期、原生0、原TLS/帧数/材料/退出门禁
和原件hash通过才B。复用W1原链，每次START至少余1小时；无续证或无证书降级许可。

两次N0直连TLS、v3、20ms完整周期、400步维护、observer/初态、worker16/8MiB、light
和正常GC一致，无relay/WPR。SC-B复用_staged_gain的10%中位改善、p99不升及max≤20ms；
控制样本通过与收益门槛单列，收益不足仍真实exit5，禁止重跑找通过。原N2/资格门禁不改。
软件独审通过及完整精确预声明先于运行；结果无论好坏均公开全部失败/维护与原生退出，
交同版本独立结果核对后停止。不自动合并/关Issue，不代表真实Wi-Fi/三机或硬件资格。

## #128 矩阵动态候选

[设计](https://github.com/GNYKCZ/secure_pid_hvac/issues/128#issuecomment-6338770182)及
[用户批准](https://github.com/GNYKCZ/secure_pid_hvac/issues/128#issuecomment-6338813023)
限定 `control-dynamic-matrix-v1` 为显式实验入口。默认、NoCERT演示和完整起摆入口不推广。
只支持 n/m/p>0、A/B/C/D/state/input 同 ell、state 逐行截断 ell、output 保留2ell。
新 `matrix-dynamic-plan-v1` 以独立域摘要绑定布局、尺度、身份与一次性资源；
`MatrixLocalStageReceipt` / `MatrixCommitAuthorization` 明确记录一个矩阵操作。
原暂存、双提交ACK、状态连续性和绝对截止语义沿用；任何未知提交结果停止会话。

M=[A B; C D]、z=[x_old;v]，每次新鲜U/V，W=UV。公开E=M−U、F=z−V后，
本方W_i+U_iF+EV_i，只有P1加入EF。前n行沿原Trunc形成下一state，后p行直接出力。
4/2/1时每方乘法材料90→41元素，含Trunc98→49元素；乘法掩码60→36元素。
这是数值元素数，不是TCP包数或性能成绩。

共同测量支持H使用现有 benchmark CLI、控制循环及供料worker。A为main32fbb112加H；
B为A加矩阵实现。manifest冻结两完整head、完整源/配置/依赖指纹及独审链接。
角色和worker在各自spawn进程核来源；共同H只给worker终报增加公开来源绑定。
四份用户交互部署配置不参与固定实验，另做字节保护，不纳入性能来源。

本Issue只使用 `.tmp/issue128-performance-budget.json` 和
`.tmp/issue128-native-invocations.json`，顺序 `M128-P0`、`M128-A`、`M128-B`。
外层原生启动器先持久记录唯一START及命令，CLI内部再占预算；退出后记录真实exit和原件hash。
共享入口和实际循环都核对当前进程的预算锁、同manifest未结束占项及原生START，
并复用同一P0/A前件判定。读取已保存manifest不能绕过占项或重放已结束调用；
这些下游核验只读取事实，不再次占项或退款。
任何启动失败或在途项均不可退款。P0一次2对预热+16对正式AB/BA交替、新鲜材料，保留全部样本；
裸数值编码、恢复和本地原语不代表IPC或完整周期，局部速度不作A的10%准入条件。
A/B各唯一一次最多1000周期，A全量零失败/零超期、真实exit0、证据与清退完整才允许B。

固定N0 mutual TLS、observer初态5°、20ms、段400、库存16/8MiB、light全样本有界历史、
正常GC，无relay/WPR/额外控制预热。批准的一次测试证书生成使用现有fixture，目标新空目录
`.tmp/issue128-matrix-certs`，A/B同链、启动余期至少1小时。证书失效停止。
运行命令仍为 `uv run secure-control benchmark` 的固定网络参数组合；必须同时提供已审精确
`--network-approval`、本Issue授权URL和匹配wire，不支持任意步数覆盖。

矩阵结果schema为 `matrix-dynamic-evidence-v1`；A为 `matrix-comparison-scalar-evidence-v1`。
矩阵资源字段为 matrix_products_consumed、scalar_equivalent_products、
multiplication_material_elements、truncations_consumed；嵌套原维护/生命周期中的products
表示该wire的operation计数，不能解释为旧标量三元组。旧结果与历史计数不回填。
B全1000 p50较A下降≥10%、p99不升、max≤20ms及完整门禁才能宣称本次收益通过；
max≤15ms另列观察余量。结果不足保留候选并停止，不追加补测、自动修复或合并。
