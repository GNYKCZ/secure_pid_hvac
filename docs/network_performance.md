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
