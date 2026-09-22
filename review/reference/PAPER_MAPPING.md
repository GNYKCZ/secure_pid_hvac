# Paper Mapping for Review

Reference: Teranishi & Tanaka, *Client-Aided Secure Two-Party Computation of Dynamic Controllers*, IEEE TCNS, 2025.

Reviewer 对照的核心位置：
- Eq. (2)：离散 LTI dynamic controller；
- Eq. (6)：fixed-point encoded controller 与 state truncation；
- Protocol 1：Beaver-triple multiplication；
- Protocol 2：masked truncation，结果允许 `w∈{-1,0,1}`；
- Protocol 3 / Eqs. (12)-(13)：Client sharing/auxiliary input -> P1/P2 shared computation -> Client reconstruction/decode；
- Sec. VII PID numerical example：parallel-form PID realization；其示例 A/B 整数化可使该 state update 不需要一般的 Trunc；Fig. 3 比较 original 与 two-party controller input error，并考察 fractional precision。

Review 标签：
- **Exact**：代码语义按论文对应定义；
- **Equivalent**：写法不同但数学/协议语义可验证等价；
- **Adapted**：为当前实验场景有意改变输入、plant 或 reference；
- **Simplified**：保留功能性效果但省略论文安全步骤；
- **Missing**：代码/文档声称存在但实际上没有对应路径。

Adapted/Simplified 本身不是 Bug；错误发生在：
- 实现与其 claim 不一致；
- 简化破坏了所比较的数学对象；
- 简化结果被拿来支持超出其证据范围的安全/理论结论。
