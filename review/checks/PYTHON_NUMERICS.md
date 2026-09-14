# Python / NumPy Numerical Review

## Integer / modular arithmetic
- `np.int64/uint64` 是否在 `% q` 之前发生 fixed-width overflow；
- Python `int` 放入 ndarray 后是否被强制成 fixed-width dtype；
- `dtype=object`/Python bigint 路径中是否又被某个 `np.asarray(..., dtype=int64)` 截断；
- 中间矩阵乘加是否沿用同一安全 dtype；
- q 很大时是否存在浮点转换导致精度丢失。

## Rounding / division / sign
- Python `round` ties-to-even 是否与代码声称的论文/quantizer rounding 相同；
- 负数 `//`, `%`, `>>`, `int()` 的语义是否匹配目标 truncation；
- centered residue decode 是否在 `q/2` 附近一致；
- integer inverse / modulo operations 是否以整数完成，没有经过 float。

## Shape / broadcasting
- `(n,)`, `(n,1)`, scalar、row/column matrix 混用是否触发静默 broadcasting；
- `squeeze()` 是否在 n=1 时改变接口语义；
- matrix `*` vs `@` 是否符合数学式；
- log arrays 是否长度/时间戳一一对齐。

## Floating-point / finite values
- NaN/Inf 是否被产生、传播、过滤或掩盖；
- equality/tolerance 是否与量级相符；
- 极小误差画 log 时对 0 的处理是否只影响展示，而没有改写原 metric。

## Python state semantics
- mutable default args；
- shallow copy / alias；
- class/global mutable state 泄漏到另一个 rollout；
- generator/iterator 被消费一次后复用；
- dict/list 缓冲区在不同 ell/seed 间复用。

## API / exception facts
- broad `except Exception` 是否吞掉数值/shape/配置错误；
- 函数失败时是否返回 `None`，而 caller 又把它转换成数值继续运行；
- warnings/errors 是否被降级成“正常结果”。
