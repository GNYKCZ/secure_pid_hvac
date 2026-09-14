# 安全算术组合门禁

Issue #9 只组合既有公开 crypto API，不改变定点数、共享、Beaver 或截断的协议语义。
它是后续通用安全运行时开始前的数值正确性门禁。

## 参数矩阵与尺度账本

CI 覆盖以下合法参数组合：

```text
(q=2147483647, lambda=8, ell=4/8/12)  -> kappa=21
(q=2147483647, lambda=7, ell=8)       -> kappa=22
(q=65537,      lambda=2, ell=4)       -> kappa=13
```

这些 `q` 均为已验证素数，且每组都满足 `kappa > ell`。固定点 payload 位宽等于该组的
`kappa`，因此 Gate 能覆盖 Protocol 2 的完整 `Z<kappa>` 消息边界，而不是仅测试较小的
固定点子区间。

每次组合试验遵循：

| 阶段 | 表示与尺度 | 必要检查 |
| --- | --- | --- |
| 定点编码 | signed payload，`2^ell` | 论文 `floor(x*2^ell+1/2)` |
| 共享与重构 | canonical residue `[0,q)` | 形状、`dtype=object`、中心化 decode |
| Beaver 乘法 | signed product，`2^(2ell)` | 一次独立 triple，测试边界精确乘积 oracle |
| Protocol 2 截断 | signed output，`2^ell` | 一次独立 `r/r'`，`w in {-1,0,1}` |
| 最终 decode | 实数近似 | 量化与允许 Trunc 误差分开审计 |

Beaver 在 `Z_q` 上重构的结果天然是 canonical residue。Gate 因此只在测试边界保存
编码 payload 的精确 Python 整数乘积，并在进入 Protocol 2 前与中心化 Beaver 重构值比较。
若二者不相等，说明乘积已经发生数学模回绕，Gate 会失败且不会创建 Trunc 掩码。这个
oracle 不属于任何生产 Server API，也不改变 Beaver 或 Trunc 的协议语义。

## 试验与重现

- 已知值：`q=2147483647`、`lambda=8`、`ell=8`、输入 `1.25` 和 `-0.75`、seed `202609`。
- 定点→共享→重构→解码：每个合法参数组合使用固定 seed 的随机 `2x3` 矩阵，其中显式
  包含零值，审计量化误差、shape 与 `dtype=object`。
- 随机门禁：5 个合法参数组合各 16 次，共 80 个独立 case；每个 case 都以同一 trial
  seed 重放一次，因而总共执行 160 次成功随机协议运行。
- 精确边界：每个合法参数组合均通过完整组合路径验证乘积为 `0`、该组
  `maximum_message=2^(kappa-1)-1` 与 `minimum_message=-2^(kappa-1)`；这覆盖零值及每组
  `Z<kappa>` 的精确上下界。
- 非法参数矩阵：Gate 明确拒绝 `ell=0`、合数 `q=65535`、不满足 `kappa > ell` 的
  `(q=257, lambda=3, ell=4)`，以及布尔 `lambda`。
- 每个 trial 使用自己的 seed，并重新创建 RNG、`BeaverMultiplier`、`SecureTruncation`、
  triple、掩码、计数器和中间份额；不会复用前一 trial 的任何状态。
- 相同外层 seed 会重放全部随机输入与 trial seed；相同 trial seed 会重放完整资源
  transcript：Beaver `(a,b,c)` 以及 Protocol 2 中心化 `(r,r')`，并重放对应的 payload、
  乘积和截断输出。资源重构仅发生在测试边界。
- 扩展或单独复现随机路径：

```powershell
uv run pytest tests/test_secure_arithmetic_gate.py -k randomized -q
```

所有 Gate 路径断言和由 Gate 包装的异常均包含 seed、trial 编号、左右输入、`q`、`ell`、
`lambda`、活动 scale 和原语阶段；给出的值足以通过同一测试命令定位具体 case。

## Gate 结果判据

通过需同时满足：

1. 编码→共享→重构→解码保持量化误差界；
2. Beaver 重构结果等于编码 payload 的精确乘积；任何数学模回绕都必须在 Trunc 前失败，
   且每个成功乘法消费一个 triple；
3. Trunc 输出与论文 rounding 相差仅 `{-1,0,1}`，且每调用消费一对随机量；
4. 大模数路径保持 Python 整数与 `object` 容器，不发生机器整数静默溢出；
5. 同一 seed 重放完整 triple/mask 资源序列与数值 transcript；
6. 零值、`Z<kappa>` 精确上下界和非法参数组合均有独立回归测试；
7. 所有原语依旧保持场景无关的 import 边界。
