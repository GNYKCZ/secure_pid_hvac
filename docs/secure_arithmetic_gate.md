# 安全算术组合门禁

Issue #9 只组合既有公开 crypto API，不改变定点数、共享、Beaver 或截断的协议语义。
它是后续通用安全运行时开始前的数值正确性门禁。

## 固定参数与尺度账本

CI 使用已验证素数 `q=2147483647`、`lambda=8`，因此：

```text
kappa = floor(log2(q)) - lambda - 1 = 21
ell   = 4, 8, 12
```

每次组合试验遵循：

| 阶段 | 表示与尺度 | 必要检查 |
| --- | --- | --- |
| 定点编码 | signed payload，`2^ell` | 论文 `floor(x*2^ell+1/2)` |
| 共享与重构 | canonical residue `[0,q)` | 形状、`dtype=object`、中心化 decode |
| Beaver 乘法 | signed product，`2^(2ell)` | 一次独立 triple，精确模乘积 |
| Protocol 2 截断 | signed output，`2^ell` | 一次独立 `r/r'`，`w in {-1,0,1}` |
| 最终 decode | 实数近似 | 量化与允许 Trunc 误差分开审计 |

## 试验与重现

- 已知值：`ell=8`、输入 `1.25` 和 `-0.75`、seed `202609`。
- 随机门禁：每个 `ell in {4,8,12}` 使用 seed `91000+ell`，各 16 次，共 48 次。
- 扩展或单独复现随机路径：

```powershell
uv run pytest tests/test_secure_arithmetic_gate.py -k randomized -q
```

失败断言包含固定 seed、trial 编号和原语阶段；同一 seed 会重新创建 RNG、
`BeaverMultiplier`、`SecureTruncation` 与中间 share，防止跨用例资源污染。

## Gate 结果判据

通过需同时满足：

1. 编码→共享→重构→解码保持量化误差界；
2. Beaver 重构结果等于编码 payload 的精确乘积，且每乘法消费一个 triple；
3. Trunc 输出与论文 rounding 相差仅 `{-1,0,1}`，且每调用消费一对随机量；
4. 大模数路径保持 Python 整数与 `object` 容器，不发生机器整数静默溢出；
5. 所有原语依旧保持场景无关的 import 边界。
