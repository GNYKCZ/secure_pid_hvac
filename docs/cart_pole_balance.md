# 小车倒立摆近直立明文平衡基线（Issue #91）

本期以 [#90 对象和 SI 信号约定](cart_pole_plant.md) 为前置，从直立附近恢复到
杆近竖直、小车近轨道中央的局部目标。平衡设计唯一可编辑来源是
[`configs/cart_pole_balance.yaml`](../configs/cart_pole_balance.yaml)；物理参数、
20 ms 采样、±10 N 已施加力界和 ±0.5 m 轨道界仍只从
[`configs/cart_pole_plant.yaml`](../configs/cart_pole_plant.yaml) 读取。
没有场景外部的 controller 状态或扰动接口。

## 工作点、线性化与离散增益

状态及理想观测为 `y=[p,p_dot,theta,theta_dot]`，单位
`[m,m/s,rad,rad/s]`；`p>0` 向右，`theta>0` 从直立向左偏。
这四项是仿真状态真值。未来真实装置可直接测量的候选通常只有带时间戳的
位置与角度；两项速度必须由场景估计并标记有效性，本期没有实现估计器。
目标 `r=[0,0,0,0]`，输入 `v=y−r`，控制器 raw 水平力 `u_raw=−K v`，
正力向右。Q/R 是本项目按上述 SI 坐标自选的数值权重，
`Q=diag(10,1,100,1)`、`R=1`；不是 CTMS 的印刷反馈增益。

令 `M,m,l,I,b,g` 与 #90 相同，`J=I+ml²`，
`Δ=(M+m)J−(ml)²`。在 `(x,F)=(0,0)` 对 #90 **非线性**双式求解析
Jacobian：

```text
A_c = [[0, 1, 0, 0],
       [0, -bJ/Δ, m²g l²/Δ, 0],
       [0, 0, 0, 1],
       [0, -bml/Δ, (M+m)mgl/Δ, 0]]
B_c = [0, J/Δ, 0, ml/Δ]^T
```

当前配置给出 `A_c` 非零加速度行约
`[0,-0.1818181818,2.6727272727,0]`、
`[0,-0.4545454545,31.1818181818,0]`，
`B_c=[0,1.8181818182,0,4.5454545455]^T`。
以 `T_s=0.02 s` 的零阶保持计算
`exp([[A_c,B_c],[0,0]] T_s)`，得到左上 `A_d`、右上 `B_d`；
离散可控矩阵 rank 为 4。生产设计使用
[SciPy `cont2discrete(method="zoh")`](https://docs.scipy.org/doc/scipy/reference/generated/scipy.signal.cont2discrete.html)，
测试另用增广矩阵指数核对。由
[SciPy `solve_discrete_are`](https://docs.scipy.org/doc/scipy/reference/generated/scipy.linalg.solve_discrete_are.html)
解 DARE 后计算
`K=(R+B_dᵀPB_d)⁻¹B_dᵀPA_d`，得到：

```text
K ≈ [-2.686135642062081, -3.422021075321116,
      25.671292765180784,  4.663385720565947]
```

K 的四个单位依次是 `N/m`、`N/(m/s)`、`N/rad`、`N/(rad/s)`。
构造 `ControllerSpec` 时 `A:(0,0)`、`B:(0,4)`、`C:(1,0)`、
`D:(1,4)=−K`、`x0:(0,)`，全部 `float64`，`scale_metadata=None`。
这是现有 `PlaintextStateSpaceRuntime` 支持的静态全状态反馈，没有虚构积分器
或 observer state。默认 5° 初态的 `u_raw,0≈−2.240242909979021 N`。

线性无饱和闭环 `A_d−B_dK` 的谱半径约 `0.975793840705157<1`；
这只说明**原点附近、理想全状态、精确 ZOH 线性模型、未限幅**时的局部数值
Schur 稳定性。实际实验始终推进 #90 的非线性 RK4 plant，并在 actuator
边界将 raw 力裁到 ±10 N；轨道越界仍由 plant 拒绝。谱半径不能证明饱和
非线性系统全域收敛、8 秒之外安全，或真实硬件稳定。

## 观测判定与记录顺序

本项目自选演示工作域 `safe_abs=[0.45 m,0.6 m/s,0.20 rad,1.0 rad/s]`，
稳定阈值 `stable_abs=[0.02 m,0.03 m/s,0.02 rad,0.05 rad/s]`。
每个更新前观测的四项绝对误差必须均不超过工作域阈值，否则立即失败，
不再调用 runtime。四项均在稳定阈值内时连续计数加一，否则清零；满
`51` 个观测（跨越 50×20 ms，即 1.0 s）才将**该次观察**标为 `stable`。
离开阈值后状态恢复为 `recovering`，即使此前曾稳定。角度连续不 wrap；
非有限观测也报告失败。工作域盒只是入域门禁，不声称盒内任意初态都收敛。

每次实验运行 `400` 个控制区间，终点 `t_400=8 s` 再观测一次而不产生
新力。终态必须仍有连续 51 个稳定观测，结果才为 `stable`；否则为
`time_limit`。`run_balance_experiment` 在场景层按以下次序记录：

```text
t_k: reference, 更新前 output → 工作域门禁/稳定计数 → v=y−r
     → 通用 runtime 输出 raw → adapter 裁成 applied
     → #90 plant.step(applied) → 成功后提交该区间的两种力
t_{k+1}: 下一次观测；t_400 只观测/判定
```

完整运行的 `time_s/state/output/reference/observed_status/stable_count` 各有
`401` 行，`raw_force/applied_force` 各有 `400` 行，力的 shape 为 `(400,1)`。
若门禁、runtime 或 plant 失败，结果 `status=failed`，携带失败步号、类别和
最后已提交前缀；不伪造剩余 8 秒轨迹，也不把失败结果当作成功图。
通用 `simulate_branch` 只提供更新前观测和 applied 力，所以本期仅由场景层
薄循环保存额外 raw 力与判定；短轨迹已与通用引擎逐步对齐。

## 预声明初态与独立明文结果

下表均使用上面的固定配置、零目标、无外扰；六组初态都属于本期局部测试集合。
`首次 stable` 是实际连续计数满 51 的观测时刻，不是线性谱结论。

| 初态 `[p,p_dot,theta,theta_dot]` | 首次 stable | 8 s 结果 | 最大 `|u_raw|` |
| --- | ---: | --- | ---: |
| `[0,0,0,0]` | 1.00 s | stable | 0 N |
| `[0,0,+5°,0]` | 3.44 s | stable | 2.240243 N |
| `[0,0,-5°,0]` | 3.44 s | stable | 2.240243 N |
| `[+0.1 m,0,0,0]` | 2.96 s | stable | 0.268614 N |
| `[-0.1 m,0,0,0]` | 2.96 s | stable | 0.268614 N |
| `[+0.08 m,0,-0.05 rad,0]` | 3.40 s | stable | 1.498455 N |

[`tests/test_cart_pole_balance.py`](../tests/test_cart_pole_balance.py) 用固定 K 字面量、
独立 CTMS 隐式双式与每区间高精度 DOP853，逐点核对 401 个状态、400 组
raw/applied 力及计数；默认 5° 的 `k=0/1/5/50/100/400` 还有冻结数值
断言。当前 RK4 与独立 DOP853 的最大状态分量差约 `2.76e-9`，最大 raw
力差约 `7.76e-9 N`，测试以 `3e-8` 绝对容差覆盖有限步数值误差。
测试也覆盖 `theta=0.25 rad` 在 `t0` 越域、
`[0.44 m,0.6 m/s,-0.2 rad,-1 rad/s]` 首步 raw 超 10 N 经限幅后次步
越域，以及 10 步时限未稳定、plant 故障和非有限观测。

在工作域内，未量化 `v` 的逐项绝对值不超过 `safe_abs`，因此仅作为后续
数值范围推导的实数粗界 `|u_raw|≤|K|·safe_abs≈13.05962 N`；实际施力
至多 10 N。此界未计定点编码误差、判定误差或网络故障，不替代 #92 的
安全范围、模数或资源证明。动画、外力事件、起摆、真实硬件及急停也不属于
本期结果。
