> **历史资料（#84）** 本页记录旧 HVAC 实验和当时的命令；文中的 `configs/hvac*` 路径已从当前用户配置目录退出，原始输入只留在 `tests/fixtures/legacy_hvac/` 供回归测试。当前实验请按 [配置索引](../configs/README.md) 运行三角色或 Fig3。

# 2R2C HVAC 条件化无限时域安全契约

## 定理与量词

Issue #38 的结论不是“默认仿真永远安全”，而是一个带明确前提的条件定理。历史 v1 配置的
reference 固定为 25°C；Issue #59 为最终快速响应 PID 新增的 schema v2 配置固定为 15°C。
对每个 `ell ∈ {32,40,48,56}`，若 reference 从证书初态起固定为对应配置声明的工作点并无限
持续、ambient 固定为 30°C、初态属于配置中的局部盒、量化和解码扰动不超过声明界、plant
二进制矩阵及来源哈希不变，且 raw control 始终严格位于 `(0,12) kW`，则对所有整数 `k >= 0`：

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
证书 SHA-256、实际编码 controller 指纹、controller state 坐标投影、payload 界，以及领域无关的
仿射 composition 记录。该记录明确给出 `v=Lz+l+Mw` 和外部状态
`z_e+=Fz+f+Gw+Hu`，并以独立 SHA-256 内容寻址。

Client 在创建参数 share、Beaver triple 或 mask 前重新验证：

1. controller 编码 payload、维数及 scale ledger 的指纹；
2. 把已安装的 A/B/C/D 代入 composition，逐项精确重建 problem 的
   transition、affine、disturbance 和 controller input 投影；
3. problem/witness 的规范摘要与全部精确数学条件；
4. controller state 和 input 投影没有越过公开 payload 界；
5. state accumulator 的 `Z<kappa>`/centered `Z_q` 门禁和 output accumulator 的 centered `Z_q`
   门禁。

运行时公开不可变 `range_verification` 摘要；`reset()` 建立新 Client/session，因而重新执行同一
验证，失败时不会替换仍可用的旧 session。

## 来源与发布

历史权威假设保留在 `configs/hvac_2r2c_infinite_safety.yaml`；最终快速响应 PID 的独立假设在
`configs/hvac_2r2c_infinite_safety_25_20_15_fast_response.yaml`。两者均冻结 plant、PID、
precision sweep 和 Pocklington prime 证据的规范文本 SHA-256、完整稳定性报告参数与内容摘要，
以及四个精度点各自的有理 witness。schema v2 还绑定 verified `resolved_source.json` 和
`resolved_plan.json` 中的 baseline ID、三源摘要、稳定性报告和 12 点矩阵。发布证书同时保存
上游 final/data manifest 的 SHA-256；原子发布前会重读两个 manifest，任一变化都拒绝发布。

报告命令只读取已经由正式 reader 完整复验的 sweep，不运行实验、仿真或绘图：

```text
uv run python -m secure_control.experiments.infinite_safety_runner \
  --assumptions configs/hvac_2r2c_infinite_safety_25_20_15_fast_response.yaml \
  --sweep-dir results/sweeps/<verified-sweep-id> \
  --output-root results/safety
```

输出目录原子包含 `certificate.json`、`report.md` 和 `manifest.json`。

## 不覆盖项

历史 fixed-25 证书与最终 fixed-15 证书是两个独立条件定理，不能互换 witness 或来源身份。最终
`25→20→15°C` 的 180 步切换轨迹也不属于 fixed-15 局部未饱和证书；前者由有限时域仿真与范围
证书支持，后者才具有 `k >= 0` 的量词。本契约不证明一般切换或饱和非线性系统，不修改密码
算法，也不声称真实建筑标定。
