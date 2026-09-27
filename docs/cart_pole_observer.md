# 两测量动态倒立摆明文基线（#107，契约版本1）

本入口在近直立有限仿真中只以位置和连续角度控制。它使用同一个
`CartPolePlant`、执行器、LQR设计和通用 `PlaintextStateSpaceRuntime`，
四维预测估计有真实内部递推。它不替换 #91 静态四输入或 #102 静态捕获路径，
不启动安全协议、持续后端、GUI或硬件。监督仍是明确标注的理想仿真真值。

实施依据：[Issue](https://github.com/GNYKCZ/secure_pid_hvac/issues/107)、
[设计评论](https://github.com/GNYKCZ/secure_pid_hvac/issues/107#issuecomment-5854827724)。
本项目参数不是论文的四水箱印刷参数或 CTMS 的连续时间增益复现。

## 运行与唯一参数来源

```powershell
uv run python scripts/run_cart_pole_observer.py configs/cart_pole_observer.yaml
uv run python scripts/run_cart_pole_observer.py configs/cart_pole_observer.yaml --disturbance 200:1 --output results/diagnostics/observer-pulse.json
```

默认400区间、8仿真秒，无外力；报告写已有被忽略的 `results/diagnostics`，
已有文件不覆盖。成功保存且终点连续stable才exit=0；失败、uncertain、time_limit、
坏配置或I/O错误均exit=1。`--disturbance STEP:FORCE_N` 可多次指定，
必须是horizon内严格递增唯一的整数步及±1N。外力记录为探索覆盖，不能输入observer。

| owner | 唯一源与派生规则 |
|---|---|
| 物理 | `cart_pole_plant.yaml`：M/m/l/I/b/g/Ts/RK4、初物理态、轨道/力界；M、Ts等可为合法有限小数 |
| 反馈和监督 | `cart_pole_balance.yaml`：Q/R、零目标、safe/stable/保持次数/horizon；K由模型和DARE重算 |
| 观测器 | `cart_pole_observer.yaml`：仅引用前两源；四正互异衰减率、两速度种子、四维初态误差假设 |
| 派生/记录 | 模型、K/L/spec、谱、保证域、来源SHA/快照由程序产生，不是另一套可编辑参数 |

默认rates=[12,14,16,18] s⁻¹、velocity seed=[0,0]，
initial_error_abs=[0,.1,0,.15]（m、m/s、rad、rad/s）。
Q/R/目标/阈值/Ts不在observer配置重复。改Ts会自动改变ZOH/极点与保持秒数，
不会暗改51个观测的计数规则。非法键、重复键、bool/字符串转数、NaN/Inf、
小数步数、不可观/控或病态设计启动前拒绝；合法参数也不承诺闭环成功。

## 数学、维度与单步时序

原物理态 `[p,v,theta,omega]`：m、m/s、rad、rad/s。theta=0直立、正向左偏，
连续记录，不wrap。设H=ml、J=I+ml²、Delta=(M+m)J−H²，解析直立Jacobian：

```text
Ac = [[0,1,0,0],
      [0,-bJ/Delta,H²g/Delta,0],
      [0,0,0,1],
      [0,-bH/Delta,(M+m)Hg/Delta,0]]
Bc = [0,J/Delta,0,H/Delta]^T
[Ap,Bp] = ZOH(Ac,Bc,Ts)
Cp = [[1,0,0,0],[0,0,1,0]], Dp=zeros(2,1)
```

K与静态builder共用原DARE；L=place_poles(Ap.T,Cp.T,exp(−rates*Ts)).gain_matrix.T。
已有SciPy的YT算法，rtol=1e−10、maxiter=200；不收敛/实际极点不符则拒绝，
不自动换增益。模型可控/可观rank=4、反馈/误差/controller/增广谱及正定残差均检查。

```text
y_k = [p_measured,theta_measured−theta_star]
u_raw,k = −K xhat_k
xhat_(k+1) = Ap xhat_k + Bp u_raw,k + L(y_k−Cp xhat_k)
ControllerSpec: A=Ap−BpK−LCp, B=L, C=−K, D=0
shapes: A(4,4), B(4,2), C(1,4), D(1,2), x0(4,)
```

全部float64、scale_metadata=None；D=0意味着本轮测量在普通运行中首先影响
下一轮力。首样本仅在进入episode时用于x0。不能改成“先校正再输出”。
无扰理想线性系统在 `[z,xhat]` 坐标的Phi为
`[[Ap,−BpK],[LCp,Ap−BpK−LCp]]`；转为 `[z,e=z−xhat]` 后对角块是
Ap−BpK、Ap−LCp。记录Phi与controller A的谱，不由Phi稳定推断任意输入的A稳定。

在t_k先校验两测量，再取独立真值供监督/诊断，保存xhat_k；
runtime.step(y_k)先输出raw再提交数学下一估计。只有raw未超界才通过原actuator，
发送指令；只有关联回执和力证据确认仿真区间完成才记录成功力。
t_N只观测/判定，不调用runtime或多发一次力。

## 非饱和契约、三种域和外力

动态路径要求 `abs(raw)<=Fmax`（等号合法），此时command=applied=raw。
超界直接 `saturation_outside_contract`，不发送、不推进、终止episode。
原静态路径限幅行为不改。若以后要限幅后续控，现step不足以回灌同轮实际施加量，
需owning Issue批准执行反馈/时序设计；不能塞“previous_applied”冒充同轮反馈。

外力按已有单区间±1N规则分账。若applied+requested超Fmax，拒绝外力、actual=0，
不对合力二次裁剪。observer不读取requested/actual/total。
`e_next=(Ap−LCp)e+Bp*d_actual+nonlinear_remainder`，扰动时估计不必精确。

| 域 | 可声明的事实 |
|---|---|
| 理想线性充分域E | W=diag([1/safe²,1/safe²])，解Phi.T P Phi−P=−W；状态行与[0,−K]力行各取a²/(h P⁻¹ h.T)，c为最小值。s.T P s≤c在无扰理想线性系统不变、采样safe且raw不饱和 |
| 有限非线性见证 | 下表预声明初态/种子/扰动，canonical RK4在线轨道/力门禁，完整独立积分对照；不证明E外所有初态成功 |
| 实际在线域 | 原safe/stable与轨道界、固定chart测量域、raw力界、有效性/身份/时序；失败终止，积分容差不扩大任何门禁 |

默认c≈3.736093718，5°测量初始化且零初速度的V≈19.33448，位于保守E之外。
E不是非线性RK4中间阶段保证，也不是任意外扰保证。局部safe角域须小于pi，
不把一个整圈当成局部直立工作域。

## 测量、执行、初始化与episode接口

`load_cart_pole_observer_design(path)` 统一编译不可变快照；
`.initialize(first_measurement,velocity_seed=None)` 交付 `ObserverInitialization`，
直接消费 `.spec`，不人工抄矩阵或读取物理初速度。

| 契约 | 内容与边界 |
|---|---|
| MeasurementSample | 不可变sample_id严格非负int、time_s、p_m、theta_rad及两个bool valid；仅两个测量，p正向右、连续theta正向左 |
| read_measurement | 固定Ts runner要求连续sample_id=k、time=kTs，时间仅允8·eps·max(1,abs(kTs))表示误差；无效/重复/缺失/乱序直接终止，不补旧值 |
| ControlCommand | command_id、episode_id、关联sample_id、target_force_n；目标是执行器力，不含外扰 |
| ActuationReceipt | 关联身份、disposition、applied_force_n或None、applied_source；rejected/accepted/unknown不证明完成，未知施加量不能填目标值 |
| 仿真回执 | 仅canonical plant.step成功才simulated_interval_completed；力来源canonical_simulation、实际applied等于command。真实ACK不支持本期成功区间证据 |
| 独立诊断/监督 | 显式注入truth_provider和force_evidence；默认ideal_simulation_truth，用[p,v,alpha,omega]复用BalanceMonitor。控制不使用真值seed/创新 |

首样本选择n=floor((theta+pi)/(2pi))，theta_star=2pi*n；已在[-pi,pi)取n=0，
避免无意义wrap舍入。整个episode固定这个分支，alpha=theta−theta_star；
不逐步wrap估计或对wrapped角差分。测量若是模角，未来provider必须先建立可信连续角，
本期不默猜圈。默认x0=[p_measured,0,alpha_measured,0]，允许显式速度种子。

初态误差界是设计前提，不能由两测量在线证明。本期仿真诊断核对初误差，超界终止，
不以真速度修复seed；不把整个允许误差盒宣称为非线性成功域。
`ObserverBalanceEpisode(initialization,runtime,episode_id=...)` 只依赖runtime.step，
不要求读取秘密state：step校验/映射两测量并调用runtime，end使旧episode永久停止。

进入须新测量、chart、种子/误差前提及新身份；退出不reset plant/连续theta/全局步号；
重新进入须新初始化，不把未知旧状态设零称延续。恢复、计算分段都不是进入事件，
不能清observer/监督计数掩盖失败。#103需另验动态捕获初误差/工作域，
不能照搬 #102 静态捕获盒。秘密初始化/材料由 #108/#109 owning路径处理。
Client未来需要速度监督时须独立因果估计或保留明确理想监督限制，不能读秘密observer。

仿真reset/原子step不表示真实设备回零或可回滚。真实驱动、抖动、标定、执行反馈、
硬件保护及20ms墙钟保证归 #110；本机仿真不能替代 #76 真三机验收。

## 真实失败前缀与报告

报告kind=`cart_pole_observer_plaintext`、version=1、computation_mode=plaintext；
源字节SHA/有效配置、派生模型/矩阵/谱、spec/x0/误差前提/范围、样本身份/两测量、
xhat、连续真值/局部监督量、计数及raw/command/applied/disturbance/total分列。
run保存前后核对源字节，allow_nan=False，结果只读，摘要由原始行复算。
`effective_options.initial_state` 对内建仿真取确实构造plant的配置/覆盖初态；
替换设备时只取已记录的首个注入诊断真值，并标记
`initial_state_source=injected_diagnostic_truth`；无可信首行时为null/unavailable，
不会把设计配置默认初态冒充外部运行初态。此诊断来源不进入控制输入或x0。
此明文研究结果不是三方writer/reader认证，也没有虚构secure分支。

正常N区间有N+1观测/N力；坏首样本可零行，后继样本失效只保留可确认区间和可用观测，
不造缺失末行。数学下一估计已提交但物理未确认时只记attempt，不混入正常估计表；
执行证据异常则uncertain、禁止重发。如果完成回执之后力证据失效，attempt注明
physical_interval_completed=true，成功前缀不接受不一致力行，不冒充物理未曾执行。
terminal仍连续stable才成功，历史稳定后扰动导致终态未稳定是time_limit。

## 本机有限结果与独立数学验证

| 初态/速度seed/外扰 | 400步终点 | 首次/恢复stable | raw峰值N |
|---|---|---|---:|
| ±5°，零速度/零seed，无外力 | stable | k172 | 2.240243 |
| [.02,.1,.05,−.15]，seed零 | stable | k174 | 1.229842 |
| 同初态，seed[.05,−.05] | stable | k162 | .825572 |
| +2pi+5°，+1N@k200 | stable | k172/k283 | 2.240243 |
| −4pi−5°，−1N@k200 | stable | k172/k283 | 2.240243 |

名义最大采样[p,v,alpha,omega]绝对值约[.102489,.265570,.0872665,.413598]SI。
初未知速度例最大估计误差约[.003275,.1,.004734,.151684]SI；
脉冲例最大误差约[.0013331,.0363138,.00290658,.0909328]SI。
六例终点逐项估计误差均小于预声明[1e−4,1e−3,1e−4,1e−3]SI。

独立oracle使用旧独立隐式质量矩阵、独立增广expm及冻结K/L，DOP853每步按自己的
测量/估计计算力，不重放生产u。完整400步六例最大state差约5.934e−9、
estimate差约3.676e−9、raw差约1.307e−8N；8子步RK4最大state差约3.702e−10，
支持3e−8SI/1e−7N容差。监督计数/步号精确匹配；runtime与展开式按1e−12核对。
失败验证含超raw界/等号邻接、超初误差、坏测量/重复身份、ACK/unknown/拒绝、
原子越轨/禁止重发、扰动后未恢复的终点和报告写入失败。
这些是有限数值证据，不是全局/永久稳定、任意扰动/误差恢复或真实硬件结论。

## #108/#109/#103交接

design.initialize同一记录给出spec、实际x0、y_abs=[safe_p,safe_alpha]、N、初误差前提、
每步实数界h_k=abs(A^k)h0+sum(abs(A^j B)y_abs)，h0=abs(x0)，
raw界abs(C)h_k+abs(D)y_abs（本期D=0）。这是实数保守界，不是实测峰值、整数payload
或模数证明；未来新初始化须重新取其实际x0，不沿用旧界。
初误差另供增广域/下游控制证明，不能由这个输入驱动粗界推出非线性物理成功。

本期状态和估计公开用于明文研究。安全阶段x0/state须P1/P2持秘密份额，
不可照搬报告公开估计；公开测量、分支、模式/切换时刻的程度由各owning Issue声明。
下游尺度ledger仍是参数/输入/state/x0的2^ell、乘法累加2^(2ell)、状态Trunc回ell、
输出2ell解码、floor(x·2^ell+1/2)及中心化Zq；#108必须针对实际矩阵/初态约束
重新证明每个累加器和Protocol 2前提/±1误差，不能用Fmax或静态0-Trunc代替。
本期没有安全执行、Trunc成本、LAN动态reader或秘密跨段实现。

## #108 有限三方动态闭环

`configs/cart_pole_observer_lan.example.yaml` 显式选择 schema 2 的
`observer_two_measurement`，只引用上文的 observer 配置；该配置继续引用原 plant 与
balance。Client 在拨号前从仿真首样本的 `p,theta`、声明的速度种子重建 spec/x0，
并核对仿真真值只作为初始误差前提。更换 plant 初态或任何来源文件都必须新建会话和
范围证明；已加载 profile 在发布前重查原始来源字节。

通用 `Client` 对编码后的 A/B/C/D/x0 先检查参数位宽，再用精确有理数矩阵幂
证明每个 `k=0…N` 的 state payload、每个 `k<N` 的 state/output 累加器；
证明包含输入端点和逐状态行 Trunc 的舍入/±1 裕量，并保存在有效配置的
`range.proof.step_bounds`。终点只验证后继 state，不执行第 N+1 轮。
`ControllerLayout` 决定每步资源；当前四维/两输入 dense 布局派生出30个乘法材料、
4个状态 Trunc，输出保持2ell尺度直接解码，不增加输出 Trunc。

有限两支分别持有 plant、episode、监视器与运行时。理想支使用明文状态空间运行时；
安全支只调用原 LAN runtime 的 `step([p,theta−theta_star])`，秘密四维估计始终留在
P1/P2。两支仅用独立诊断真值做工作域/稳定监督；raw 超过±Fmax时协议轮次可能已提交，
但不得发送力或发布成功。`insecure_tcp` 仅供无认证、无加密本机实验；原 mTLS 路径
仍可用。仿真 20ms 网格不构成 20ms 墙钟或真实硬件保证。

正式结果沿用八字段 `trajectory.csv` 与原子 writer。动态场景 version 4 的
`cart_pole_evidence.json` schema 3 另记 N+1 两测量/物理真值、N个公开 raw/施力/
扰动、监督和终点；metadata 记双提交轮次、唯一 round/resource ID 与实耗。
reader 从有效配置重建 spec 与编码范围，独立重放物理/理想递推，并以编码矩阵和
Trunc误差包络核验安全 raw；随机秘密估计本身不能由公开结果精确重建。
hash/reader 检测不一致，不对能重写全部文件者提供密码学真实性。旧静态侧证据
version 1/2 的 reader 分支保持原行为。

本期交给 #109 的后继含义是：完成第 N−1 轮后双方各持有 `x̄_N mod q` 的一份份额，
尺度为 `2^ell`；它与控制器指纹、q/κ、session/全局步 N 及新鲜材料边界绑定。
Client 只知公开输出和确认的物理前缀，不知道 `x̄_N`。本期没有跨段续算；下一段
不能重用初态 `x0`、旧材料或本期有限范围证明。
