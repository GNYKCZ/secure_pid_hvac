# 2-out-of-2 加法秘密共享约定

`secure_control.crypto.secret_sharing` 在与定点模块一致的 canonical residue
`[0, q)` 上实现 2-out-of-2 additive sharing。它只处理整数和容器 shape，不解释
定点数的尺度；调用方必须沿用其已有的尺度账本。

## 分发与重构

对消息 `m mod q`，分发端逐元素取独立随机数 `r in Z_q`，并产生：

```text
share_1 = r
share_2 = m - r mod q
```

重构为：

```text
(share_1 + share_2) mod q
```

`AdditiveShare` 只保存一份 canonical residue，不包含对方 share、消息或重构接口。
`TwoPartySharing.share()` 返回的二元组仅存在于分发端；后续参与方接口应只接收一个
`AdditiveShare`。`reconstruct()` 仅适合客户端或测试边界，不能作为未来服务端的便利接口。

## 线性运算

`add`、`subtract` 和 `multiply_public` 均可由两方各自对其单份 share 局部执行，
无须重构消息。公开常数加减具有一个必要约定：为表示共享消息加/减常数，只能更新
事先指定的一份 share，另一份必须保持不变；若两方都加同一常数，重构值会改变两次。

所有输入 share 必须已经是 canonical residue。公开消息与公开常数可以是有符号整数，
分发或局部运算时会规范化到 `[0, q)`。标量可与数组组合；两个非标量输入必须同形，
避免隐式广播掩盖元素错配。

## 随机性

正常路径不传入 RNG，并使用 `secrets.randbelow(q)` 为每个 share 元素独立采样。测试可以
显式注入 `random.Random(seed)` 以复现 share 序列；该伪随机源仅用于测试，不是生产协议
随机性的替代品。本模块不因本地测试通过而声称生产级密码学安全。

## 边界

实现逐元素使用 Python `int` 与 `dtype=object`，不经过固定宽度整数中间值，因而可处理
大于机器字长的模数。它不包含秘密乘法、Beaver 三元组、截断、角色编排或通信机制。
