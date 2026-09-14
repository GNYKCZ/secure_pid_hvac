# Fixed-Point / Secret-Sharing Protocol Review

本模块审查“代码声称实现的协议语义”是否成立，不要求真实云部署，也不把本地进程数量当作密码学证明。

## Paper mapping first
先用 `reference/PAPER_MAPPING.md` 给关键路径标：`Exact / Equivalent / Adapted / Simplified / Missing`。只有 claim 与实际不一致，或 Simplified 路径被当成论文安全协议时，才报告。

## Fixed-point scale ledger
从代码实际运算追踪关键变量 scale：real / `2^ell` / `2^(2ell)` / other。
检查：
- encode 后 scale；
- matrix×state/input 中间 scale；
- state rescale/trunc 后 scale；
- controller output scale；
- final decode scale。

任何一步不能只靠变量名猜测。

## Signed `Z_q`
- Share/Reconst 在 `mod q` 下成立；
- 需要解释为 signed payload 的 residue 使用一致的 centered mapping（或可证明等价方法）；
- 负值没有在 decode 时变成接近 q 的巨大正值；
- `q/2` 边界处理一致。

## Beaver multiplication
若声称 Protocol 1 / Beaver multiplication：
- `c=a*b mod q`；
- opened values 是 masked differences，而不是原 secret；
- secret×secret 每次标量乘法所需 randomness 没有不安全复用；
- matrix multiplication 的 triple 消耗与标量乘法路径一致；
- public×share 没被错误当成 secret×secret，反之亦然。

## Truncation
若声称论文 Protocol 2：
- opened value 是 masked value；
- mask 的生成/范围/复用与代码 claim 一致；
- modular inverse 与 bit shift/scale 一致；
- 正负输入边界语义一致；
- reconstruction 的误差范围与论文允许的 `w∈{-1,0,1}` 兼容。

若实际做的是 reconstruct -> 普通 trunc -> reshare，只能标为 Simplified；如果输出/README 把它称为论文安全 Trunc，则是 claim mismatch。

## Paper PID special case vs general encoded controller
论文 Sec. VII 的 PID 数值例中 A/B 可为整数，state update 可以避免一般 fixed-point A/B 所需的 state Trunc。Reviewer 先确认代码属于哪种情形，再判断是否漏/多了 rescale；不要机械套用一种分支。

## Range safety
分别检查：
1. **machine overflow**：fixed-width dtype 在 `%q` 前溢出；
2. **mathematical wraparound**：即使 bigint 正确，payload 超出 intended centered range 后 `mod q` 改变语义。

若代码只对已测轨迹做 range diagnostic，只能支持“tested trajectory 未观察到 wraparound”，不能自动升级为满足论文理论 q bound。

## Claim boundary
单进程/单机的 Client/P1/P2 逻辑仿真可以支持 protocol-flow / arithmetic-semantics claim；不能仅凭它支持真实主机隔离、网络安全、TLS、延迟或 production cryptographic security claim。
