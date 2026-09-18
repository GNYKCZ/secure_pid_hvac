# 2R2C HVAC 局部闭环稳定性

## 分析对象

本报告旁路只读消费 `configs/hvac_2r2c_plant.yaml` 与
`configs/hvac_2r2c_pid_baseline.yaml`。plant 使用 exact zero-order hold，状态顺序为
`x_p=[T_air,T_wall]`；位置式 PID 延续运行时的更新前状态输出语义，状态顺序为
`x_c=[I,e_previous]`。因此闭环状态固定为：

```text
z = [I, e_previous, T_air, T_wall]
```

报告同时记录矩阵维度 `4` 与状态单位 `[degC_second,degC,degC,degC]`，避免消费者仅凭
位置猜测积分状态和两个温度状态的量纲。

该分析不会重新整定 PID，也不修改 plant、执行器范围、参考轨迹、仿真结果或安全协议。

## 闭环矩阵与仿射项

对误差 `e=r-C_p x_p`，控制器与 plant 分别为：

```text
x_c(k+1) = A_c x_c(k) + B_c e(k)
u(k)     = C_c x_c(k) + D_c e(k)
x_p(k+1) = A_p x_p(k) + B_p u(k) + E_p T_ambient
```

固定 reference 与 ambient 不进入齐次矩阵。局部未饱和闭环为：

```text
Phi = [[A_c,        -B_c C_p],
       [B_p C_c, A_p-B_p D_c C_p]]

g(r,T_ambient) = [B_c r;
                  B_p D_c r + E_p T_ambient]
```

每个工作点独立求解 `(I-Phi)z*=g`，再计算 `e*`、raw `u*`、归一化平衡残差、
`cond(I-Phi)` 以及到执行器上下界的两个裕量。只有 raw `u*` 严格处于 `(0,12) kW`
时，该工作点才标记为 `applicable`；位于边界或越界时为 `not_applicable`，奇异、病态或
数值不可判定时为 `indeterminate`。

令 raw control 对状态偏差的行向量为：

```text
K_u = [C_c, -D_c C_p]
```

报告给出的 `unsaturated_linf_radius = min(lower_margin,upper_margin)/||K_u||_1` 是保证
control 不触及饱和的局部充分条件。它不是吸引域、正不变集或安全范围证明。

## 当前冻结结果

默认单位圆灰区半宽为 `1e-9`，特征对归一化残差阈值为 `1e-10`。当前四个特征值约为：

```text
-0.0014666066
 0.8708694351
 0.9527571162
 0.9993811396
```

因此谱半径约为 `0.9993811396`，到单位圆的裕量约为 `6.1886045e-4`，分类为
`stable`。数值风险同时保留在报告中：`cond(Phi)` 约 `6.4141e4`，右特征向量矩阵条件数
约 `2.3787e3`，`cond(I-Phi)` 约 `5.0009e7`。稳定裕量较小且平衡方程条件数较高，不能只
摘取 `stable` 状态而丢弃这些诊断。

固定室外温度 `30°C` 时，三个 reference 的平衡 raw control 与最近执行器边界裕量为：

| reference (°C) | raw control (kW) | 最近边界裕量 (kW) | 未饱和 L∞ 半径 |
|---:|---:|---:|---:|
| 15 | 1.525940997 | 1.525940997 | 1.759280193 |
| 20 | 1.017293998 | 1.017293998 | 1.172853462 |
| 25 | 0.508646999 | 0.508646999 | 0.586426731 |

三个工作点均严格位于执行器内部，但各自裕量不可共享。

## 运行与机器读取

在仓库根目录使用当前 `uv` 环境运行：

```text
uv run python -m secure_control.scenarios.hvac.stability_runner \
  configs/hvac_2r2c_plant.yaml configs/hvac_2r2c_pid_baseline.yaml
```

CLI 输出标准 JSON，包含闭环矩阵、状态顺序、谱、容差、残差、条件指标、逐工作点报告、
plant/PID 文件 SHA-256、假设和 claim boundary。复杂特征值拆为 real/imaginary 字段，报告
不泄露可变 NumPy 数组。

## 结论边界

`rho(Phi)<1` 仅覆盖固定 reference/ambient 工作点附近、执行器未饱和、明文、精确实数
线性模型的渐近稳定性。它不证明：

- 饱和切换系统或全局闭环稳定；
- 定点编码、量化、截断误差下的稳定性；
- 安全协议执行正确性或协议安全；
- 无限时域状态/控制范围安全。

Issue #38 已在独立旁路中同时消费来源 hash、实际量化矩阵、扰动界和精确不变集 witness；不能
把本页的 `stable` 单字段重解释为无限时域证书。完整条件见
[2R2C HVAC 条件化无限时域安全契约](infinite_horizon_safety.md)。
