# 小车倒立摆对象与物理信号（Issue #90）

本页固定后续 #91–#93 使用的对象边界；此阶段只有明文 plant，没有控制器、
网络会话、范围证明、动画或真实驱动。参数唯一可编辑来源是
[`configs/cart_pole_plant.yaml`](../configs/cart_pole_plant.yaml)。

## 来源、坐标与方程

采用 [University of Michigan CTMS 单杆倒立摆建模教程](https://ctms.engin.umich.edu/CTMS/index.php?example=InvertedPendulum&section=SystemModeling)
的非线性式 (3)、(6)，保留杆绕质心转动惯量及小车黏性摩擦。
[MIT Underactuated Robotics 的 cart-pole 推导](https://underactuated.mit.edu/acrobot.html#cart_pole)
提供无杆惯量、无摩擦特例的交叉核对；本实现没有采用该简化。
CTMS 的角度从向下位置起算；这里令 `theta = theta_CTMS − π`。小车中心位置
`p` 以轨道中央为零、向右为正；`theta=0` 表示杆竖直向上，正角表示杆质心
向左、逆时针偏转。状态及 `output()` 顺序恒为
`[p, p_dot, theta, theta_dot]`，单位为 `[m, m/s, rad, rad/s]`。
`step(control)` 的 `control` 必须为 shape `(1,)` 的**已施加**水平力 `[F]`，
单位 N，向右为正。`output()` 是理想全状态观测的独立快照。

记 `M` 为小车质量、`m` 为摆杆质量、`l` 为铰点到杆质心距离、`I` 为杆绕
质心转动惯量、`b` 为小车黏性摩擦、`g` 为重力加速度，`v=p_dot`、
`ω=theta_dot`、`J=I+ml²`。每次连续时间导数计算解以下非线性双式：

```text
[(M+m), -ml cos(theta)] [p_ddot    ]   [F - bv - ml ω² sin(theta)]
[-ml cos(theta), J]    [theta_ddot] = [mgl sin(theta)          ]
```

导数为 `[v, p_ddot, ω, theta_ddot]`。行列式
`Δ=(M+m)J−m²l² cos²(theta) ≥ (M+m)I+Mml² > 0`；实现求解此双式，
不把线性化方程当作对象动力学。零状态、零力使导数和每一步状态精确为零。
零状态下 `F=+1 N` 的瞬时 `p_ddot=1.818181818… m/s²`、
`theta_ddot=4.545454545… rad/s²`；负力使两者反号。

角度连续累计，不按 `±π` 取模，也不按“近直立”阈值截断。动力学数学式
允许大角度，但本系列首期只研究直立附近恢复；稳定判定由 #91 定义。

## 参数、时间和边界

| 配置字段 | 当前值 | 含义 / 来源 |
| --- | ---: | --- |
| `cart_mass_kg` | 0.5 kg | CTMS 教学示例 `M` |
| `pole_mass_kg` | 0.2 kg | CTMS 教学示例 `m` |
| `com_length_m` | 0.3 m | CTMS 教学示例 `l`，不是杆全长 |
| `pole_inertia_kg_m2` | 0.006 kg·m² | CTMS 教学示例 `I`，绕杆质心 |
| `cart_friction_n_s_per_m` | 0.1 N·s/m | CTMS 教学示例 `b`，仅小车黏性摩擦 |
| `gravity_m_per_s2` | 9.8 m/s² | CTMS 教学示例 `g` |
| `sample_period_s` | 0.02 s | 本项目仿真选择 |
| `rk4_substeps` | 4 | 本项目仿真选择：每步 4 个 0.005 s RK4 子步 |
| `initial_state` | `[0, 0, 0.08726646259971647, 0]` | 本项目选择：中央、静止、左偏 5° |
| `track_center_limit_m` | 0.5 m | 本项目选择：小车中心 `|p|≤0.5 m` |
| `max_applied_force_n` | 10 N | 本项目选择：已施加力 `|F|≤10 N` |

这些值不是论文实测装置参数或硬件标定。当前模型没有摆轴摩擦、电机动力学、
传感器噪声、延迟或外部扰动力：`d≡0`，也没有扰动接口。力在
`[t_k,t_{k+1})` 内零阶保持。每个 RK4 阶段和候选子步终点检查有限性与
`|p|`；任一检查失败就抛错，plant 保持本次 `step` 前的状态，不裁剪、不反弹。
只在这些离散检查点检查位置，不保证检查点之间的连续轨迹不会越过机械限位。
力界由 plant 拒绝越界命令，不等同于执行器的自动限幅或硬件安全证明。

通用引擎读取 `t_k` 更新前 `output()`，再生成并施加 `F_k`；`step` 返回
`t_{k+1}` 观测。plant 的失败原子性不意味着引擎会回滚已推进的 controller。
配置严格拒绝缺失、额外或重复字段、错误类型、非有限值、非正物理正量、
负摩擦与越轨初态。

## 独立数值核对

[`tests/test_cart_pole_plant.py`](../tests/test_cart_pole_plant.py) 从上面的隐式
双式另写 `numpy.linalg.solve` 右端，并用 SciPy `solve_ivp(method="DOP853")`
在每个 0.02 s 的常力区间独立求解。测试固定初始 5° 和力序列
`[0.5, -0.25, 0, 0.75, -0.5] N` 的单步及五步输出常量，先核对独立求解值，
再以 `1e-8` 绝对误差核对四子步 RK4；当前五步的最大偏差约
`1.87e-9`（角速度），容差覆盖固定步长截断误差及平台浮点差异。
测试没有调用生产 RHS 生成预期值。

## 未来真实设备信号

设备侧至少需提供带单调时间戳的 `p [m]`、`theta [rad]`，并转换到相同的
中心、直立零点及正方向。`p_dot [m/s]`、`theta_dot [rad/s]` 通常由带时间戳的
位置/角度观测估计；应标注估计来源和有效性，不把仿真真值冒充编码器测量。
执行器接收已限幅的水平**力目标** `[N]`；若电机只接受电流/电压，力转换
及限流是后续硬件接口职责。测量对应 `t_k`，命令作用于随后一个采样区间。
真实采样抖动、量化、延迟、碰撞限位和急停不由此仿真契约证明。#93 若增加
外力事件，需明确与执行器力分账及采样边界。安全协议、定点量化、Trunc 与
模运算在此阶段不适用。
