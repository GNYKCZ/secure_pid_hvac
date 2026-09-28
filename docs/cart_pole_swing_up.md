# 下垂起摆明文可行性（Issue #102）

实施依据：[设计评论](https://github.com/GNYKCZ/secure_pid_hvac/issues/102#issuecomment-5854012523)。
这是独立的有限明文研究入口，验证当前物理对象的起摆、捕获和保持。
现有三角色近直立配置、默认持续 GUI、finite 模式及正式 verified reader 保持原语义。

## 运行与报告

在项目根目录运行，无需启动 P1/P2：

```powershell
uv run python scripts/run_cart_pole_swing_up.py configs/cart_pole_swing_up.yaml
uv run python scripts/run_cart_pole_swing_up.py configs/cart_pole_swing_up.yaml --direction -1
uv run python scripts/run_cart_pole_swing_up.py configs/cart_pole_swing_up.yaml --direction 1 --disturbance 600:1
uv run python scripts/run_cart_pole_swing_up.py configs/cart_pole_swing_up.yaml --direction -1 --disturbance 600:-1
```

`--direction` 只允许整数 ±1，指首次小车施力方向；下垂点杆的初始角加速度与其反向。
`--disturbance STEP:FORCE_N` 可重复，替换配置事件列表；步号必须递增、唯一且在 horizon 内，
力只允许 ±1 N，保持一个完整控制区间。无该参数时使用配置原事件。
基线源是 `configs/cart_pole_swing_up.yaml`，相对其路径引用原 plant/balance YAML。
未知、重复、遗漏、非法类型/shape/有限性及来源不一致均在运行前拒绝。

默认把报告写入已忽略的 `results/diagnostics/cart-pole-swing-up-<唯一标识>.json`，
也可传 `--output <new-report.json>`。已有文件不会覆盖。
stdout 给出报告路径、真实终止状态、摘要和转换；只有最终 `observed_success` 返回 exit=0。
物理失败或 `time_limit` 仍保存诊断与可信前缀，`goal_met=false`、exit=1。
配置或 I/O 失败不会宣告已保存成功。报告没有三方正式 artifact 或认证含义。

JSON `kind=cart_pole_swing_up_plaintext`、`version=1`、`computation_mode=plaintext`，包括：

- 成功完成 N 个区间的 N+1 行 `time_s/state/output/upright_angle_rad`；初始观测无效时只留诊断。
- N 行 `(N,1)` 的 `raw_force/applied_force/disturbance_force/total_force` 和区间模式/限幅标记。
- 每个观测的模式、状态、原稳定计数、捕获尝试和内盒计数；转换记录含观测步号、秒及实际 z。
- 已完成区间的实际/拒绝外力事件；未提交的尝试单独保存，不混入成功力数组。
- 终点目标、历史首次 stable、失败观测/区间索引和分类诊断；摘要只由原始行派生。
- 原物理/平衡及有效起摆配置、effective 初态、SI 单位、源 YAML 快照/字节摘要和实际 Git/dirty/Python 信息。

脚本运行前冻结来源，结束时核对字节未变。CLI 覆盖值写在有效配置中，原 YAML 快照保留。
API 的配置/结果是独立快照；数组只读、观测/转换不可变，`to_report()` 返回新对象。
直接 API 的 `write_swing_up_report(..., provenance=...)` 可附来源；未提供时明确标记 unavailable。
无需重执行控制即可用普通 JSON 读取器复算摘要；这不是旧正式 reader 的新格式分支。

## 物理、角度和控制律

唯一物理源仍是 [plant 配置](../configs/cart_pole_plant.yaml) 和[冻结双式](cart_pole_plant.md)：
`M=.5 kg,m=.2 kg,l=.3 m,I=.006 kg·m²,b=.1 N·s/m,g=9.8 m/s²`。
`Ts=.02 s`、每步4个 RK4 子步、`|p|≤.5 m`、`|F_total|≤10 N` 均未修改。
本次实例显式初态 `[0,0,π,0]`；原源默认5°初态没有改写。

原始观测 `y=[p,v,θ,ω]` 使用 `[m,m/s,rad,rad/s]`。θ=0直立、正角向左，θ连续累计。
场景另建 `α=(θ+π) mod(2π)−π`、`z=[p,v,α,ω]`。
已在 `[-π,π)` 内的角保持原值，避免无意义加减π影响边界；其余做周期映射。
不改变原状态或角速度、不以 wrapped 角差分估计ω，也不添加阈值 epsilon。
负启动最终原 θ≈2π，与正启动最终 θ≈0 代表同一局部直立目标。

令 `H=ml=.06 kg·m`、`J=I+ml²=.024 kg·m²`，相对支点的摆杆能量为：

```text
E_p = Jω²/2 + Hg cosθ      E* = Hg = .588 J
e_E = E_p−E*              dE_p/dt = H cosθ·ω·p_ddot
a_des = −k_E e_E ω cosθ − k_p p − k_d v
u_raw = [(M+m)−H²cos²θ/J]a_des + bv + Hω²sinθ − (H²g/J)sinθcosθ
```

基线 `k_E=8 m/(J·s),k_p=16 s⁻²,k_d=8 s⁻¹`。
前10区间固定 `kick_direction×1 N` raw 控制力以打破下垂对称性，之后能量反馈；
捕获重试不重新启动。启动不是外力，不依赖 `sin(π)` 的舍入误差。
原 `CartPoleAdapter` 只对 raw 力限幅一次。
外力在控制计算后锁存：若 `|applied+requested|>10 N`，拒绝请求、实际 d=0，
不能把合力二次裁剪后称外力已完整施加。重放只消费实际接受的冻结事件，非法重放合力直接失败。

力映射由带惯量/摩擦的质量矩阵消元得到，没有除以cosθ的奇点；
`Δ=(M+m)J−H²cos²θ≥.0132>0`。
能量是摆杆相对支点的量，不是车杆总机械能。
回中PD、采样、饱和和外力不保留纯能量反馈的理想耗散结论，因此没有全局收敛保证。

## 观测驱动的阶段与失败

每个整数观测仅消费一次。顺序为观测门禁→监督转换→模式控制→限幅→外力→原子plant步。
终点观察和转换后判定，不再计算或施加第N+1次力。

| 配置/规则 | 基线与行为 |
|---|---|
| 运行速度包络 | `abs(v)≤3 m/s,abs(ω)≤15 rad/s`，含启动期间；仅研究包络。 |
| capture enter/exit | 内盒 `[.35,.5,.15,.8]`，外盒 `[.40,.55,.18,.9]`；逐项 enter < exit < 原 safe。 |
| 首次捕获 | 启动结束、冷却结束、在内盒且 αω≤0；该观测即使用 canonical LQR，不等待保持完成。 |
| 捕获保持 | 连续3观测在内盒才进入balance，跨2Ts=.04s；落在两盒间继续LQR但计数清零。方向只在首次进入使用。 |
| 捕获中止 | 原safe内、外盒外返回swing_up，销毁本次monitor/内盒计数；至少5个推进区间后再尝试。 |
| 原安全域 | 每个capture/balance观测先用原BalanceMonitor检查；超safe立即失败，不能借中止或重置掩盖。 |
| 次数/时限 | 最多3次捕获；每次100步；未进入balance的全局时限为600步。边界同刻合法进入balance优先，不能在捕获到期时借中止逃逸。 |
| 保持/恢复 | balance继续同一个LQR/monitor。离stable但仍在safe内只报告recovering、计数归零；连续51观测跨1s后恢复stable。超safe终止。 |
| 1500步终点 | 最后仍balance且原monitor stable、没有失败才goal_met；历史曾stable不能替代终点保持。 |

分类原因包括 observation_invalid、nonfinite、overspeed、track_limit、numeric_control/step、
capture/acquisition_timeout、capture_attempts_exhausted、balance_domain_exceeded、replay_force_limit。
失败是吸收态。原plant任一RK4阶段越轨/非有限则不提交部分步；
下一有限观测的速度/safe门禁失败则保留已经发生的区间和失败观测。
不能形成合法有限新观测时只留最后可信前缀与诊断，不补齐失败轨迹或写JSON NaN/Infinity。

## 验证与可声明结果

```powershell
uv run python --version
uv run pytest tests/test_cart_pole_swing_up.py tests/test_cart_pole_plant.py tests/test_cart_pole_balance.py -q
uv run pytest
uv run ruff check .
```

当前名义两方向、无外力和对应±1N@k600的四条30s见证：capture k232、balance k234、
首次stable k370；最大采样 `|p|≈.3824047502 m,|v|≈2.2534895168 m/s,|ω|≈9.8056323433 rad/s`；
raw峰值约17.2733589210N、applied峰值10N、7个饱和区间。
无外力终点稳定计数1181；扰动后重新stable在k653，终点计数898。
这些是冻结输入的有限数值可行性见证，不是任意初态/扰动或永久稳定性结论。

预声明探针固定其它参数，保留全部结果：

| 探针 | 本机结果 |
|---|---|
| k_E=4 | k600 acquisition_timeout，未捕获，不报告成功。 |
| k_E=16 / 800 | 均在已完成第19区间后的观测超速；保留失败观测和19个真实区间。 |
| ±1N@k10、±1N@k233（正启动） | 四例均在1500步终点stable；首次stable分别k369/391及k377/365。 |
| p初态±.01m、θ初态π±.01rad（各自单独变化，正启动） | 四例均在1500步终点stable；不据此推广到任意初态。 |

因此不能声称整个增益区间可行；当前推荐仅冻结8/16/8基线。

测试用自己的质量矩阵、能量式、冻结独立K、阶段判据和DOP853在自身状态闭环；
逐20ms常力区间核对完整N+1状态/N力、模式/事件/计数，另取21个密集点核对轨道。
不重放生产控制值，不调用生产RHS。全轨迹SI绝对容差分别为
`[5e−8,2e−7,1e−6,2e−6]`，raw力为5e−6N；8子步RK4误差下降支持这些容差。
阈值单元测试直接测试等号/相邻浮点，没有用该积分容差放松guard。
另有预声明起摆/捕获外力±1N@k10/k233、坏增益、越轨、超速、溢出、重试/冷却/超时、
重复观测、历史stable后终点失去保持、非法重放、JSON/I/O及同机重跑/实例隔离测试。
完整实际命令结果以Issue实施报告为准；没有GUI、真三机、硬件或墙钟实时验收。

## 交给 #103 的计算与信息边界

| 阶段/事项 | 能力与尚需决定/证明 |
|---|---|
| startup | ±1N的有限序列；方向/步数是否公开须声明。明文启动不能证明之后非线性计算安全。 |
| swing_up | sin/cos、ω²、能量乘积、状态相关力映射及分支，无法对原四维输入表示为一个固定ControllerSpec。Client预计算特征只证明特征后的线性部分安全。 |
| capture/balance | 复用静态原LQR：A(0,0)、B(0,4)、C(1,0)、D(1,4)、x0(0,)；输入是显式z−r。原阶段安全实现每步4乘法、0状态Trunc；旧输入/2ell输出证明只在该阶段适用。 |
| 守门域实数包络 | `abs(p)≤.5,abs(v)≤3,abs(ω)≤15,abs(α)≤π`；E_p∈[−.588,3.288]J、e_E∈[−1.176,2.7]J；基线保守 `abs(a_des)≤356 m/s²,abs(u_raw)≤264.47N`。这是公式粗界，非峰值实测或定点/模数证明。 |
| 全程安全 | 新做三角近似与误差、平方/乘法/尺度恢复、秘密比较/选择/计数、周期角度及模式切换；逐中间量分析位宽、量化、Trunc、中心化q和一次性资源成本。不能只按±10N applied选择q。 |
| 阈值计算 | 入口/方向/外盒/计数在近阈值处的舍入须单独分析，不能无条件把浮点判据照搬秘密定点。 |
| 混合路线 | Client明文起摆后安全LQR须#103明确批准、标注各阶段控制来源并升级范围/独立对照/正式reader；#102没有预先批准此路线。 |
| 信息公开 | 本研究公开全部状态/力/参数/外力/模式。未来模式、切换时刻或转数可泄露阈值满足等事实，#103须明确其公开程度与安全声明。 |

有限轨道内的控制可行性与安全算术可行性分别验证。这里不改变LAN profile、
P1/P2、core、generic engine、旧物理或stable/safe阈值，也不实现#103或#76。

## #103 独立明文完整路线（部分交付）

新版 [Issue #103](https://github.com/GNYKCZ/secure_pid_hvac/issues/103) 要求明文与安全两条各自完整的路线。
当前 `plaintext_full` 只交付明文起摆→明文动态捕获/平衡/恢复；上文的旧静态研究入口仍为默认，
其历史 JSON 和回归不改。运行示例：

```powershell
uv run python scripts/run_cart_pole_swing_up.py configs/cart_pole_swing_up.yaml --route plaintext_full
uv run python scripts/run_cart_pole_swing_up.py configs/cart_pole_swing_up.yaml --route plaintext_full --direction -1 --disturbance 600:-1
```

`--observer` 可指定 #107 三源 observer YAML，默认 `configs/cart_pole_observer.yaml`。
其 plant/balance 必须与起摆来源相同；合法物理参数变化须重新派生 observer 设计。
每个 route 自己新建 canonical `CartPolePlant`、测量/阶段历史和控制状态。新路线的控制输入仅为
`MeasurementSample` 的 p 与连续 θ：k=0 明示零速度种子，k=1 用一阶后差，k≥2 用三点因果后差；
先差分连续 θ，再为监督映射局部 α。仿真四维真值只供诊断报告，不进入控制力或阶段判定。

进入捕获的同一观测，以两测量和该步因果速度初始化 #107 四维明文 observer；
随后先用旧控制器状态计算力、再更新 observer 状态。`balance` 的稳定盒外恢复继续同一 observer。
若退出局部 safe 域但仍满足轨道和速度全局门禁，则在该已确认观测转回起摆，废弃本次 observer，
按冷却/捕获尝试与重新计时规则再捕获；轨道、超速、数值或采样失效则停止。
raw 控制力由原执行器限幅，外力由原设备按合力限值接受或拒绝，失败只保留可确认前缀。

新报告 `kind=cart_pole_plaintext_full`，除原物理/力/阶段行外，含 N+1 两测量、因果估计、
每区间明文控制来源、动态 observer 更新前状态及每次捕获初始化。`state/output` 明确是仿真诊断真值；
Beaver/Trunc 资源计数恒为 0。它仍是明文研究 JSON，不是三方正式 verified 产物；
没有安全起摆、v3 安全 reader 或 GUI 安全路线通过的声明。上述安全部分等待 #103 新版设计的公开阶段、
非线性数值/协议和 epoch 契约获用户决定后再实施。
