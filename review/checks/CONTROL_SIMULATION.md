# Discrete-Time Control Review

只验证当前代码和声明是否数学自洽，不规定项目应该采用哪一种 PID 或 plant 架构。

## Time and units
- 使用当前 Issue / 配置实际声明的 horizon、`Ts`、plant time constant/gain，检查单位一致；
- 使用当前实验的参考轨迹或设定值，检查切换边界和采样定义一致；
- 若边界不落在 sample 上，实际采用的切换规则与项目声明一致；
- plot 横轴单位与真实时间一致。

## Closed-loop signal direction
- tracking error、actuator 正方向、plant gain 的符号整体一致；
- heating/cooling 约定没有导致正反馈；
- saturation/limits 的单位与 controller output 一致。

## Discrete controller semantics
若代码声明使用
`x[k+1]=A x[k]+B e[k]`, `u[k]=C x[k]+D e[k]`，检查实际执行顺序是否真的用 `x[k]` 计算 `u[k]`。

若 ideal 使用 direct PID、secure 使用 state-space，只在代码/文档声称两者是“同一控制器”时检查离散公式、滤波、初始化是否等价。

## Fair comparison
比较路径之间检查：
- 同一 `Ts`；
- 同一 plant equation/params/initial temperature；
- 同一 controller params/initial state；
- saturation、anti-windup、derivative filter、measurement handling 一致，除非实验明确把它们作为变量；
- secure feedback 没有读取 ideal plant runtime output。

## State / timing boundaries
- plant/controller update 的先后顺序与所声明的离散模型一致；
- 第一个 sample、setpoint 切换 sample、最后一个 sample 没有错一拍；
- log 的 `u[k]`, `y[k]`, `r[k]` 对应同一时间语义。
