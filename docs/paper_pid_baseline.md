# #69 论文 PID 明文基线的来源门禁

本页记录 [设计评论](https://github.com/GNYKCZ/secure_pid_hvac/issues/69#issuecomment-5792415912)
可独立验证的控制器部分，以及原始闭环仍然缺少的证据。论文版本固定为
[Teranishi–Tanaka arXiv:2503.02176v3 §VII](https://arxiv.org/html/2503.02176v3#S7)。
这里的控制器输入是论文 plant 输出 `y(k)`，不是 HVAC 的 `reference-temperature`；
输出是未裁剪的 `u(k)`，没有 reference、饱和、anti-windup 或扰动。

| 项目 | 来源、当前实现与边界 |
| --- | --- |
| PID 结构 | v3 §VII：`A=[[2-Nd,Nd-1],[1,0]]`，`B=[[1],[0]]`，`C=[[c1,c2]]`，`D=[[d]]`；`c1=Ki*Ts-Nd²*Kd/Ts`，`c2=(Nd-1)*Ki*Ts+Nd²*Kd/Ts`，`d=Kp+Nd*Kd/Ts`。`PaperPidDesign.to_controller_spec()` 按该式生成通用 `ControllerSpec`。 |
| 印刷实例 | v3 §VII：`A=[[1,0],[1,0]]`、`B=[[1],[0]]`、`C=[[2.7368927,-2.96540833]]`、`D=[[-5.01071167]]`、`x_c(0)=[0,0]`。`paper_sec_vii_controller_spec()` 直接使用这些印刷系数，不以反推的 gains 重算。对应 `Nd=1`，不能由此实例宣称非平凡导数平滑。 |
| 采样与 plant 初态 | v3 §VII：`Ts=0.1 s`，`x_p(0)=[100,100,100,100]ᵀ`，plant 为 [38] Eq. (2) 的 SISO benchmark，`α=0.2`。这些值已定位，但因缺少可核实的作者所用状态 realization，**尚未形成可运行原例配置或 plant 断言**。文献未核实的物理单位不赋予 °C/kW 等场景含义。 |
| 时间索引 | v3 Eq. (1)/(2)：每步以更新前 `x_c(k)` 和 `y(k)` 计算 raw `u(k)`，然后更新 `x_c(k+1)` 与 plant；Fig. 3 的范围是 `k=0…50`，共 51 个样本。本仓库的 `PlaintextStateSpaceRuntime` 已实现该控制器顺序，测试只验证已知输入序列，不冒充原 plant 序列。 |

差分 oracle 仅在测试中独立实现：`I(0)=0`、`d(-1)=0`、`y(-1)=0`，
`d(k)=(1-Nd)d(k-1)+(Nd*Kd/Ts)*(y(k)-y(k-1))`，
`u(k)=Kp*y(k)+I(k)+d(k)`，`I(k+1)=I(k)+Ki*Ts*y(k)`。
测试从印刷实例反推的 gains 只用于对照，不是论文另给的一组精确原始 gains；
因此印刷小数之外的精度和作者原始调参值均不作声明。`Nd=2/3` 用于有限步公式检验，
不表示这些变体的闭环稳定。运行 `uv run pytest tests/test_paper_pid.py` 可重验这些断言。

## 原始 plant 与声明边界

主论文 §VII 的 [38] 是 Åström–Hägglund 的
[*Benchmark systems for PID control*](https://doi.org/10.1016/S1474-6670(17)38238-1)，
不是用户补充的 [Li–Ang–Chong, *PID Control System Analysis and Design*](https://www.academia.edu/13906459/STANDARD_STRUCTURES_OF_PID_CONTROLLERS_Parallel_Structure_and_Three_Term_Functionality_The_transfer_function_of_a_PID_controller_is_often_expressed_in_the_ideal_form_32_IEEE_CONTROL_SYSTEMS_MAGAZINE)。
后者可辅助理解一般 PID 并联式和滤波，但既不是 [38] 的 plant 方程，也不提供此数值例的
`A_p/B_p/C_p`、离散化与 `x_p(0)` 所在的状态坐标。

即便核实 [38] 的连续传递函数，任选状态空间 realization 仍会使同一个数值向量
`[100,100,100,100]ᵀ` 对应不同的初始输出；不同离散化还会改变后续 `y/u`。
在取得作者原例的离散 `A_p/B_p/C_p` 与状态坐标/离散化说明之前，不生成
`paper_pid_original` 配置，也不把自选对象的轨迹、sidecar 或 Schur 判定称为
“论文原数值复现”。论文控制器公式和给定输入序列已达到**数学等价**；
Issue #69 的作者原 plant 来源与原例明文控制输入验收仍未完成。

## 经批准的 paper-inspired 串联对象基线

[追加设计决策](https://github.com/GNYKCZ/secure_pid_hvac/issues/69#issuecomment-5796460314)
允许另行构造**明确标注的论文衍生实验**，但不放宽上述原例来源门禁。
[38] 原文 Eq. (2) 给出连续传递函数
`G(s)=1/[(s+1)(1+αs)(1+α²s)(1+α³s)]`；论文 v3 §VII 取 `α=0.2`、
`Ts=0.1 s`、`x_p(0)=[100,100,100,100]ᵀ`。来源只规定输入到输出的传递关系，
**没有规定作者的状态坐标**。

本项目选择四级串联一阶环节的逐级输出作 `x_1..x_4`：

```text
dot(x_1) = -x_1 + u
dot(x_2) = (x_1 - x_2)/α
dot(x_3) = (x_2 - x_3)/α²
dot(x_4) = (x_3 - x_4)/α³
y = x_4
```

于是所选坐标下的初值 `[100]×4` 给出 `y(0)=100`；该等式不能倒推作者也使用
同一坐标。`scenarios/paper_pid/plant.py` 对连续 `(F,G,H,J)` 使用 SciPy 的
`cont2discrete(..., method="zoh")`，假定每个采样间隔内未裁剪 `u(k)` 恒定，
程序派生 `A_p/B_p/C_p/D_p`，不在 YAML 中抄存第二套矩阵。该对象无 HVAC
温度/功率单位，也不加入 reference、饱和、anti-windup、噪声或扰动。

`scenarios/paper_pid/baseline.py` 每步按 `x_p(k), x_c(k), y(k) → raw u(k) →`
`x_p(k+1), x_c(k+1)` 执行，共记录 `k=0..50` 的 51 行。CSV 的十列依次是
`k,time_seconds,x_p_1..x_p_4,y,x_c_1,x_c_2,raw_u`；状态、输出与控制量
均是当前 `k` 的值，`x_p/x_c` 是更新前状态。控制器仍由论文印刷的
`paper_sec_vii_controller_spec()` 提供，未重新整定。

从仓库根目录重跑：

```powershell
uv run python -m secure_control.experiments.paper_pid_runner --config configs/paper_pid_cascade_zoh.yaml
```

产物位于忽略提交的 `results/csv/paper_pid_cascade_zoh/<run_id>/`，包含单支
`trajectory.csv` 和 `metadata.json`。后者记录来源 URL、配置 SHA256、Git head/dirty、
所选坐标与 ZOH、派生矩阵、CSV SHA256、完整六维闭环的 Schur 数值诊断及
`paper-inspired` 声明。它**不使用**双支 ideal/secure 八字段 schema；数值轨迹可
重复生成，但独立 run ID 不要求相同。用 `uv run pytest tests/test_paper_pid_baseline.py`
复验连续传递函数、ZOH、51 点时间对齐、差分 oracle、产物读回和错误配置拒绝。

Schur 报告只针对这里明确选择的 `A_p/B_p/C_p`，不是作者原闭环的稳定性证明；
51 个有限样本也不能替代无限时域安全证明。此产物不得称作者原始 Fig. 3
逐点复现；原例 AC1/AC3 不能仅凭本产物判为通过或据此关闭 Issue。
