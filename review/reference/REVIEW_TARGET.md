# Review Target Facts

本文件只记录本次 Review 已知的目标事实，用作验收参照；它不是开发设计文档，也不指定代码结构。

根据当前任务，Reviewer 应验证实现是否与以下声明一致：
- 这是一个 Python HVAC 温度控制仿真；
- 总仿真时间为 3 小时；
- 参考温度分段为第一小时 15°C、第二小时 20°C、第三小时 25°C；
- 存在 ideal/original 控制结果与论文式 two-party/fixed-point 路径的比较；
- 主要结果至少包含实际温度随时间变化，以及 ideal 与 secure/control-path 的控制输入差异（类似论文 Fig. 3 的比较目标）；
- 论文用于协议、fixed-point 和 input-error comparison 的参考；HVAC plant/setpoint 是项目适配，不应自动声称复现论文原始 numerical example。

如果被审仓库中的 authoritative requirement 与这里不同，报告冲突并以用户在本轮明确指定的要求为最高项目验收依据。
