# 定点编码与模算术约定

本文件定义 `secure_control.crypto.fixed_point` 的数值边界。它只描述通用整数、
定点数和有限模环，不依赖任何场景或控制器类型。

## 参数与尺度账本

`FixedPointContext(modulus=q, integer_bits=k, fractional_bits=ell)` 使用：

- 普通实数编码尺度：`2^ell`；
- 编码 payload 范围：`[-2^(k-1), 2^(k-1)-1]`；
- 模环存储：canonical residue `[0, q)`；
- 乘法后的中间尺度：`2^(2*ell)`。

构造上下文时会验证上述 payload 范围能被中心化模表示容纳。`q` 不限制于
机器字长；实现逐元素使用 Python 任意精度整数，因此不会依赖 `int64` 中间值。

普通编码采用论文指定的规则：

```text
encode(x) = floor(x * 2^ell + 1/2)
```

这与 Python 的 `round()` 不同。特别地，`ell=1` 时，`encode(-0.25) == 0`，因为
`floor(-0.5 + 0.5) == 0`。

Python `int` 和 `fractions.Fraction` 会在不转换为 `float` 的路径上完成缩放与上述
取整。因此，在声明 payload 范围内的大整数不会因为浮点有效位数有限而静默丢失低位。
当解码分数位数为零时，`decode` 返回 Python `int`；数组返回 `object` dtype 的 Python
整数，以同样避免仅为解码而损失大整数精度。其他分数位数仍解码为有限浮点近似值。

## 模表示与有符号恢复

`to_residue` 将整数以 `% q` 转为 canonical residue。`from_residue` 只接受已规范化的
`[0, q)` 输入，并恢复：

```text
[-floor(q/2), ceil(q/2)-1]
```

因此偶数模数的 `q/2` 位于负端；例如 `q=16` 时，residue `8` 恢复为 `-8`。
该约定必须由未来分享、重构和截断实现共同使用，不能在各模块中各自定义。

## 乘法与截断边界

`multiply_residues` 仅执行 `Z_q` 模乘法，两个普通尺度输入相乘后仍带有
`2^(2*ell)` 尺度。它不执行截断，也不会把结果伪装成普通 `2^ell` 数据。

该 API 把输入 residue 恢复为当前上下文声明的 `k` 位 payload，并在取模前计算精确
Python 整数乘积。若该乘积越出中心化 `Z_q` 区间，API 会以“数学模回绕”错误拒绝，
而不会返回一个可能被误解为小 payload 的 residue。例如，`q=257` 时，`100 * 100`
不会静默变成中心化值 `-23`。

未来截断协议负责将乘积恢复到约定尺度。上述检查只能覆盖本次乘法中可见的两个
operand 和精确乘积；任何局部 API 都无法从一个已经在上游回绕、且恰好落回合法范围的
residue 推断其历史值。因此，协议集成仍须依据已知输入范围建立全局的无回绕证明。
`decode_residue` 也会拒绝明显超出 `k` 位 payload 范围的中心化代表元。

## 输入与 shape

编码、模转换、加法与乘法均接受标量、向量和矩阵。涉及模整数的输出数组使用
`dtype=object`，其中每个元素均为 Python `int`。解码在分数位数非零时使用浮点数组；
零分数位时使用 Python `int` 或 `object` dtype 数组以保留精度。非法参数、非有限实数、
非 canonical residue、超出 payload 范围、可检测的乘法数学回绕，或无法安全转为有限
浮点数的输入都会显式报错。
