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

对超过 64 位的 q，内建 Miller--Rabin 检查只能筛除已检测到的合数，不能替代外部素数
证书。因此生产调用方仍必须把 q 作为已验证的素数提供；本项目测试使用可确定验证的素数。

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
