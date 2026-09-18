# 2R2C HVAC 条件化无限时域安全契约

## 定理与量词

Issue #38 的结论不是“默认仿真永远安全”，而是一个带明确前提的条件定理。对每个
`ell ∈ {32,40,48,56}`，若 reference 从证书初态起固定为 25°C 并无限持续、ambient 固定为
30°C、初态属于配置中的局部盒、量化和解码扰动不超过声明界、plant 二进制矩阵及来源哈希
不变，且 raw control 始终严格位于 `(0,12) kW`，则对所有整数 `k >= 0`：

- 增广状态 `[I,e_previous,T_air,T_wall]` 留在已验证的鲁棒正不变椭球内；
- controller state/input payload 与 state/output accumulator 不发生已排除的越界；
- 空气温度、墙体温度、raw/applied control 均满足证书中的约束；
- 执行器不触及饱和，因此证书使用的单一仿射闭环动力学持续有效。

该结论同时证明初始集合包含和一步鲁棒闭包；归纳法给出无限时域量词。它不是把有限 180 步
区间传播外推到无限时域。

## 精确验证对象

通用 `core.invariance` 只处理精确有理数问题：

```text
z(k+1) = Phi z(k) + a + G w(k),  |w_j(k)| <= wbar_j
E = {z : (z-z*)^T P (z-z*) <= r^2}
```

验证器逐项检查平衡方程、`P` 对称正定、`gamma < 1`、严格 Lyapunov 收缩、每列扰动的
`P`-范数上界、`r(1-gamma) >= sum(eta_j*wbar_j)`、初始盒全部顶点包含，以及每条线性安全
约束的精确对偶范数与上下界。所有运算使用约分后的整数分子/正分母；证书摘要来自排序的
UTF-8 JSON，不依赖平台浮点打印。

验证器有固定维数、约束数、顶点数和整数位数预算。数学反例返回 `rejected`；超出资源预算
返回 `indeterminate`；两者均不能进入协议资源创建。

## 实际量化闭环与扰动

证书使用安全运行时真正编码后的 A/B/C/D，而不是名义 PID 小数：A/B 为零分数位整数路径，
C/D 按每个 `ell` 的 `floor(x*2^ell+1/2)` payload 再精确解码。2R2C exact-ZOH 的 binary64
矩阵以 `as_integer_ratio()` 转成精确有理数，并在报告中保存 `float.hex()` 快照与模型摘要。

扰动分开建模：

- controller input 编码误差：每步至多半个 LSB；
- state Trunc 误差：A/B 为整数路径，严格为零，所以 Protocol 2 计数为 0；
- actuation decode 误差：至多 `2^-48 kW`；
- plant roundoff：本冻结模型明确声明为零；改变该假设必须生成新证书。

“Protocol 2 为 0”表示本控制器状态更新不需要安全截断，不表示协议没有执行，也不削弱
Protocol 1 的乘法、模数范围或闭环证书门禁。

## 协议绑定与 fail closed

`ControllerRangeContract` 有三种互斥模式：`finite_horizon`、旧的
`independent_input_invariant`、以及 `closed_loop_invariant`。第三种模式携带完整 problem/witness、
证书 SHA-256、实际编码 controller 指纹、controller state 坐标投影和 payload 界。

Client 在创建参数 share、Beaver triple 或 mask 前重新验证：

1. controller 编码 payload、维数及 scale ledger 的指纹；
2. problem/witness 的规范摘要与全部精确数学条件；
3. controller state 和 input 投影没有越过公开 payload 界；
4. state accumulator 的 `Z<kappa>`/centered `Z_q` 门禁和 output accumulator 的 centered `Z_q`
   门禁。

运行时公开不可变 `range_verification` 摘要；`reset()` 建立新 Client/session，因而重新执行同一
验证，失败时不会替换仍可用的旧 session。

## 来源与发布

权威假设在 `configs/hvac_2r2c_infinite_safety.yaml`。它冻结 plant、PID、precision sweep 和
Pocklington prime 证据的规范文本 SHA-256，以及四个精度点各自的有理 witness。

报告命令只读取已经由正式 reader 完整复验的 sweep，不运行实验、仿真或绘图：

```text
uv run python -m secure_control.experiments.infinite_safety_runner \
  --assumptions configs/hvac_2r2c_infinite_safety.yaml \
  --sweep-dir results/sweeps/<verified-sweep-id> \
  --output-root results/safety
```

输出目录原子包含 `certificate.json`、`report.md` 和 `manifest.json`。

## 不覆盖项

默认 180 步基线以 15°C reference 和 30°C 初温启动，首步 raw control 为 12.875 kW，超过
12 kW 上界并进入饱和。因此它明确不在本局部未饱和证书覆盖内。本 Issue 不证明一般切换或
饱和非线性系统，不重新整定 PID，不重跑 sweep/仿真，不修改密码算法，也不声称真实建筑标定。
