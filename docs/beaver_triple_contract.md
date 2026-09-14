# Beaver 三元组与一次性消费约定

`secure_control.crypto.beaver` 实现论文 Protocol 1 的标量 2-out-of-2 Beaver 乘法。
该模块只处理 canonical residue、单份 share 与三元组生命周期；不包含定点尺度恢复、
截断、场景语义或网络隔离。

## 三元组

预处理阶段独立抽取 `a`、`b in Z_q`，计算 `c=a*b mod q`，并分别共享三者。
每个参与方只持有一个 `BeaverTripleShare(a_i, b_i, c_i)`，不持有对方份额或完整的
`a`、`b`、`c`。默认随机源是 `secrets.randbelow(q)`；测试可注入带 seed 的
`random.Random`，但不能将其当作正常协议随机性。

## Protocol 1 映射

每方先局部计算：

```text
d_i = x_i - a_i
e_i = y_i - b_i
```

仅在公开边界重构 `d=d_1+d_2` 与 `e=e_1+e_2`。不重构 `x` 或 `y`。随后各方计算：

```text
z_i = e*a_i + d*b_i + c_i
z_0 = z_0 + d*e
```

因此重构结果为 `e*a + d*b + c + d*e = x*y mod q`。公开项 `d*e` 只能归属第 0 方；
两方都加会重复计入，任何一方都不加则会漏计。

## 生命周期与资源计数

一个三元组必须经历以下严格顺序：两方各自生成一次遮蔽差值、一次公开 `d/e`、两方各自
完成一次输出计算。任一步重复、缺少另一方或混用不同三元组都会报错。乘法器公开
`created_triples`、`consumed_triples` 和 `pending_triples`，用于测试资源计数。

本 Issue 只实现 scalar-first 路径。向量/矩阵乘法需要按元素或矩阵乘法索引分配独立三元组，
必须在独立 Issue 中实现与验证，不能复用这里的标量资源。

## 安全边界

本地代码验证的是 Protocol 1 的算术语义和资源约束，不等同于进程、主机或网络隔离，也不构成
生产级安全证明。未来服务端接口应只接收各自的输入 share、三元组份额和公开 `d/e`。
