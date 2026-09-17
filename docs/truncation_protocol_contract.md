# Protocol 2 安全截断约定

本模块复现论文 Protocol 2 的标量截断消息流。论文使用中心化集合
`Z<k> = {-2^(k-1), ..., 2^(k-1)-1}` 与中心化模约简，而不是 Python `%` 的非负余数。

## 参数

`SecureTruncation(sharing, ell, security_parameter=lambda)` 要求素数模数 `q`，并定义：

```text
kappa = floor(log2(q)) - lambda - 1 > ell
m       in Z<kappa>
r       in Z<kappa - ell + lambda>
r_prime in Z<ell>
```

`inverse_scale` 是 `inv(2^ell, q)`。`paper_round_divide` 使用论文的中心化低位，等价于
`floor(m / 2^ell + 1/2)`；它不是普通非负余数除法。

模数验证由 `crypto.primes.verify_prime_modulus` 唯一负责：

- `q < 2^64` 使用固定 bases 的确定性 Miller--Rabin 判据，报告方法
  `deterministic_miller_rabin_64_v1`；当前 31-bit 与 61-bit 基线无需额外证据。
- `q >= 2^64` 时，Miller--Rabin 只可筛除检测到的合数，不能产生 verified 结论。调用方必须
  提供 `pocklington_v1` 证据；缺失证据以 `evidence_required` 明确失败。
- 证据包含公开来源、版本、证书 ID、canonical SHA-256 和完整本地证书。来源字符串仅用于追溯，
  不能代替数学验证；运行时不访问网络。

Pocklington 证书对 `n-1` 的已知不同素因子部分 `F` 验证：

```text
F divides n-1
F^2 > n
pow(a_i, n-1, n) == 1
gcd(pow(a_i, (n-1)/p_i, n) - 1, n) == 1
```

小于 `2^64` 的因子由 MR64 确定验证；更大的因子必须递归携带证书。实现使用纯 Python 整数，
不以浮点 `sqrt` 判断覆盖条件，并限制证书 bit length、递归深度、节点数和指数，检测递归循环。
`PrimeVerificationError.reason_code` 是稳定机器接口，包括 `composite`、`evidence_required`、
`certificate_hash_mismatch`、`incomplete_factorization`、`invalid_witness` 等；异常文本不应作为唯一判断。

HVAC YAML 可选证据结构为：

```yaml
security:
  modulus: <integer>
  modulus_evidence:
    method: pocklington_v1
    source: <public source>
    source_version: <version>
    certificate_id: <stable id>
    certificate_sha256: <canonical lowercase sha256>
    certificate:
      candidate: <same modulus>
      factors:
        - prime: <known prime factor>
          exponent: <positive integer>
          witness: <integer>
          certificate: <optional recursive certificate>
```

`HvacScenario -> SecureStateSpaceRuntime -> Client -> SecureTruncation` 显式传递同一不可变证据；
runtime reset 会重建 Client 并再次通过统一入口验证。有效配置快照只保存 modulus 十进制字符串、
bit length、method、status、source、source version、certificate ID/hash，不复制完整证书树。

## Protocol 2 映射

两方各自计算：

```text
[[m_r]] = [[m]] + 2^ell [[r]] + [[r_prime]] + 2^(ell-1)
```

只有 P2 调用 `p2_send_masked`，发送其单份 `[[m_r]]_2`。只有 P1 调用
`p1_reconstruct_masked`，并得到中心化 `m_r`。随后：

```text
P1: inv(2^ell,q) * ([[m]]_1 + [[r_prime]]_1
                     - ((m_r - 2^(ell-1)) mod 2^ell))
P2: inv(2^ell,q) * ([[m]]_2 + [[r_prime]]_2)
```

P2 没有任何接收 P1 消息的 API。重构输出允许与 `paper_round_divide(m)` 相差
`w in {-1, 0, 1}`，不能错误地要求恒等于普通 floor。

## 随机性与边界

每对 `r/r_prime` 都有一次性生命周期：两方遮蔽、P2 发送、P1 重构、两方完成输出。重复使用
或混用资源会失败。默认抽样使用 `secrets.randbelow`；固定 seed 的 `random.Random` 仅用于测试。

本地实现验证 Protocol 2 的算术和消息可见性语义，假设双方 semi-honest、互不串通，并有新鲜
随机量；它不等同于进程隔离、网络安全或完整统计安全证明。

素数报告中的 `verified` 仅表示本地验证器检查通过 MR64 或 Pocklington 定理前提；它不证明参数
生成过程、随机源、模数位长、协议部署或整个控制系统达到生产安全等级。#15 仍须独立选择并证明
适合各 precision 点的 `q/kappa/k/ell/lambda`，本契约不预选该参数。
