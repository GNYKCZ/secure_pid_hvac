# 论文复现范围与实现对照

本页是 Issue [#65](https://github.com/GNYKCZ/secure_pid_hvac/issues/65) 的可审查
基准，供 A05/#69、A06/#70、A09/#73 和 A11/#75 在各自 Issue 中引用。它只记录
论文、当前实现和已发布证据之间能够成立的对应关系；不是新的运行时契约，也不授权实现
论文 PID、四水箱、网络传输或 Dashboard。

## 固定来源与读法

| 项目 | 固定值 |
| --- | --- |
| 仓库基线 | `origin/main` `4e86ca1340eec14e81e1ac9c18fea6ea4202468a`（2026-09-22） |
| 论文版本 | Teranishi–Tanaka，[arXiv:2503.02176v3，2025-12-26](https://arxiv.org/html/2503.02176v3) |
| 本页的论文定位 | 使用该版本的 section、equation、protocol、assumption 与 figure 编号；HTML 版没有稳定页码时，以这些编号为准。 |
| 论文原例引用 | [38] Åström–Hägglund, *Benchmark systems for PID control*；[39] Johansson, *The quadruple-tank process*。论文参考文献条目在 [v3 References](https://arxiv.org/html/2503.02176v3#bib.bib38) 与 [bib39](https://arxiv.org/html/2503.02176v3#bib.bib39)。 |

四个互斥的声明等级如下。一个对象可拆成“通用机制”和“论文数值例”两行，不能用前者
抬升后者的等级。

| 等级 | 含义 |
| --- | --- |
| **论文原数值复现** | 相同论文对象、参数、时间网格和可核验输出均已运行并有可访问证据。 |
| **数学等价** | 当前实现的公式/协议契约和测试可对照论文同一机制；不表示论文数值例或部署安全已复现。 |
| **场景适配** | 复用论文思想或通用机制，但 plant、输入语义、控制器、采样或指标为本仓库场景选择。 |
| **尚未实现** | 当前 `main` 没有可运行的对应场景、参数化配置和正式轨迹；不得据通用能力推断为已复现。 |

`results/` 按仓库策略不提交。本页只引用
[`docs/final_hvac_evidence_chain.md`](final_hvac_evidence_chain.md) 中记录的 artifact ID、
manifest 和生成 commit；本次未取得其原始目录，因而不把它重新表述为本轮已复验的 CSV。

## 机制对照矩阵

| 论文对象与要求 | 当前实现与测试证据 | 等级与允许的声明 |
| --- | --- | --- |
| §II Eq. (2)：`x_c(t+1)=Ax_c(t)+By(t)`、`u(t)=Cx_c(t)+Dy(t)`；输出使用更新前 state | [`core/controller.py`](../src/secure_control/core/controller.py) 的 `ControllerSpec(A,B,C,D,x0)`，以及 [`execution/runtime.py`](../src/secure_control/execution/runtime.py) 和 [`tests/test_plaintext_runtime.py`](../tests/test_plaintext_runtime.py) | **数学等价**。runtime 的入口命名为 `v`，它是场景层构造的通用 controller input；只有论文原例才可直接把它称为 `y`。 |
| §II Eq. (3)、Assumption 2：完整 plant+controller 闭环 `Phi` Schur stable；Eq. (4) 的 `||u(t)-u_hat(t)|| <= epsilon` | [`core/stability.py`](../src/secure_control/core/stability.py)、[`scenarios/hvac/stability.py`](../src/secure_control/scenarios/hvac/stability.py)、[`docs/hvac_closed_loop_stability.md`](hvac_closed_loop_stability.md)、[`docs/infinite_horizon_safety.md`](infinite_horizon_safety.md) | **场景适配**。当前证书限于冻结 HVAC 闭环及其前提；不能由 PID controller matrix、有限步实验或 localhost 运行推导论文原例的 Assumption 2。 |
| §II Assumption 3：P1/P2 半诚实、不串通，且论文假设安全 peer-to-peer channel | [`protocol/roles.py`](../src/secure_control/protocol/roles.py)、[`tests/test_two_party_protocol.py`](../tests/test_two_party_protocol.py)、[`execution/localhost_runtime.py`](../src/secure_control/execution/localhost_runtime.py)、[`docs/localhost_transport.md`](localhost_transport.md) | **数学等价**（角色/份额协议语义）。本机单进程、多进程或 loopback 后端均不证明 TLS、认证、跨主机抗攻击或生产部署安全。 |
| §III Eqs. (5)–(6)：`floor(x*2^ell+1/2)` 编码、中心化 `Z_q`、state aggregate 后按 `ell` 截断，输出以 `2^(-2ell)` 解码 | [`crypto/fixed_point.py`](../src/secure_control/crypto/fixed_point.py)、[`protocol/roles.py`](../src/secure_control/protocol/roles.py)、[`docs/fixed_point_contract.md`](fixed_point_contract.md)、[`tests/test_fixed_point.py`](../tests/test_fixed_point.py)、[`tests/test_two_party_protocol.py`](../tests/test_two_party_protocol.py) | **数学等价**，限已支持的 scalar-first primitive 和通用 state-space 路径。代码以 `[0,q)` 存储 residue，并显式映射回论文的中心化表示；它不是另一套模语义。 |
| §IV Definition 1：2-out-of-2 sharing；`Reconst(Share(m)) = m mod q` | [`crypto/secret_sharing.py`](../src/secure_control/crypto/secret_sharing.py)、[`docs/secret_sharing_contract.md`](secret_sharing_contract.md)、[`tests/test_secret_sharing.py`](../tests/test_secret_sharing.py) | **数学等价**。生产角色接口不向任一 server 交付另一份 share；reconstruction 位于 Client/测试边界。 |
| §IV Protocol 1：Beaver `Mult`、公开 masked `d/e`、每个标量乘积使用独立 triple | [`crypto/beaver.py`](../src/secure_control/crypto/beaver.py)、[`docs/beaver_triple_contract.md`](beaver_triple_contract.md)、[`tests/test_beaver.py`](../tests/test_beaver.py)、[`tests/test_two_party_protocol.py`](../tests/test_two_party_protocol.py) | **数学等价**。triple 生命周期受资源 identity 约束；固定测试 seed 只为可复现，不允许跨乘法或跨 round 复用。 |
| §V-A Protocol 2：`kappa > ell`、素数 `q`、fresh `(r,r')`、输出误差 `w in {-1,0,1}` | [`crypto/truncation.py`](../src/secure_control/crypto/truncation.py)、[`docs/truncation_protocol_contract.md`](truncation_protocol_contract.md)、[`tests/test_truncation.py`](../tests/test_truncation.py)、[`tests/test_prime_contract.py`](../tests/test_prime_contract.py) | **数学等价**（通用路径）。每次调用的辅助量独立；测试覆盖正负数、边界和允许误差，不能把该 unit-level 证据称为论文 Fig. 4 运行证据。 |
| §V-B Protocol 3 / Eqs. (9)–(13)：Client 离线分享 A/B/C/D/x0；每步分享 measurement/input 和 auxiliary；P1/P2 更新 state share 并返回 output share；Client reconstruct/decode output | [`protocol/roles.py`](../src/secure_control/protocol/roles.py)、[`protocol/coordinator.py`](../src/secure_control/protocol/coordinator.py)、[`execution/secure_runtime.py`](../src/secure_control/execution/secure_runtime.py)、[`docs/two_party_protocol_contract.md`](two_party_protocol_contract.md)、[`tests/test_two_party_protocol.py`](../tests/test_two_party_protocol.py)、[`tests/test_secure_runtime.py`](../tests/test_secure_runtime.py) | **数学等价**。一般 A/B 路径对每个已聚合 state row 只截断一次；不会在每步重构 controller state。当前实现为同一 canonical Protocol 3 调度提供多种 execution backend，不等于论文网络模型的完整实现。 |

## 论文数值例参数账本

### Sec. VII PID / Fig. 3

论文的 parallel PID 映射为

```text
A = [[2-Nd, Nd-1], [1, 0]];  B = [[1], [0]]
C = [c1, c2];                D = d
```

其中 `c1/c2/d` 与 `Kp/Ki/Kd/Nd/Ts` 的关系见论文 §VII。实例固定为
`A=[[1,0],[1,0]]`、`B=[[1],[0]]`、`C=[2.7368927,-2.96540833]`、
`D=-5.01071167`、`Ts=0.1 s`、`epsilon=2^-10`、`lambda=80`、`k-ell=8`、
`x_p(0)=[100,100,100,100]^T`、`x_c(0)=[0,0]^T`。论文只给出“可选择 256-bit
prime `q`”，没有给出唯一的模数、seed 或逐点原始轨迹。

| 对象 | 当前 `main` 事实 | 等级 |
| --- | --- | --- |
| 有 derivative filter 的论文 PID 和 [38] Eq. (2) SISO plant | `scenarios/hvac/pid.py` 实现的是场景 PID：`v=r-T_air`、无 derivative filter、场景执行器饱和；没有 [38] plant 或论文参数配置。 | **尚未实现** |
| Fig. 3 的 `||u(t)-u_hat(t)||`，`t=0..50` | 没有论文 PID 原例 runner、配置、artifact 或曲线。 | **尚未实现** |
| 精度列 | §VII 实例句和 Fig. 3 图注均为 `{32,40,48,56}`，但紧邻正文一句写成 `{32,40,58,64}`。后续 A06 拟采用前者，因为同段实例和图注相互一致；必须在实现 PR 中保留该原文冲突并复核论文 PDF 图例，不能静默“修正”。 | **待实施时复核** |

### Sec. VII four-tank observer / Fig. 4

论文给出 four-tank operating point `h^0=(12.4,12.7,1.8,1.4) cm`、
`v^0=(3,3) V`、`gamma=(0.7,0.6)`、`Ts=0.5 s`，并取
`x_p(0)=[10,10,10,10]^T`、`x_c(0)=[0,0,0,0]^T`；其 4-by-4 `A`、
2-by-4 `B/C` 矩阵列在论文 §VII，且走 Protocol 2。物理模型来源是 [39]。

| 对象 | 当前 `main` 事实 | 等级 |
| --- | --- | --- |
| [39] four-tank plant、observer matrices、MIMO input/output 与 `Ts=0.5 s` | `scenarios/` 只有 HVAC；没有 four-tank scenario、配置、controller spec、验证或 artifact。 | **尚未实现** |
| Fig. 4 的四精度误差轨迹及 Protocol 2 运行证据 | 无原例 runner/轨迹。通用 Protocol 2 测试并不形成此数值例。 | **尚未实现** |

若要将任一上述项提升为“论文原数值复现”，需要取得并核验论文 PDF/补充数据、[38] 的原 plant
方程及 [39] 的模型/离散化细节；若原始曲线数据、具体 `q` 或随机材料不可得，最高只能声明参数
和方法级对照或趋势比较，而不能称逐点、bitwise 或严格数值复现。

## 当前 HVAC 证据的正确归类

[`configs/hvac_2r2c_precision_sweep_definition.yaml`](../configs/hvac_2r2c_precision_sweep_definition.yaml)
固定当前 HVAC 2R2C sweep 为 `ell={32,40,48,56}`、三个测试 seed、`lambda=80` 和本仓库的
256-bit prime。它与 Fig. 3 共享精度比较的**方法**，但不是论文 PID plant、时间网格、控制器、
measurement 输入或原始数据。

| 当前证据 | 实际语义 | 等级与禁止的推论 |
| --- | --- | --- |
| 2R2C HVAC 双闭环与 sweep | 场景层拥有 `reference -> v=r-T_air`、2R2C plant、60 s/180 步、PID、`[0,12] kW` actuator；[`docs/precision_sweep.md`](precision_sweep.md) 记录结果范围。 | **场景适配**。不能称论文 Fig. 3 原例。 |
| `control_ideal/control_secure` 和 Fig. 3 adapted | 正式证据记录的是 actuator 后的 **applied** control；原始控制误差只作数值机制诊断。见 [`docs/secure_execution_evidence.md`](secure_execution_evidence.md)。 | **场景适配**。不能把 applied-control 指标改称论文 Eq. (4) 的未裁剪原例 `u-u_hat`。 |
| 整数 A/B no-Trunc 路径 | 当前 PID 的 A/B 是零 fractional-bit 整数；每步 Protocol 1 仍执行，但 Protocol 2 计数为零。见 [`tests/test_hvac_dual_loop.py`](../tests/test_hvac_dual_loop.py) 和 [`docs/final_hvac_evidence_chain.md`](final_hvac_evidence_chain.md)。 | **场景适配**。它不证明 Protocol 2 在完整 HVAC 闭环或论文 Fig. 4 中实际执行。 |
| final HVAC evidence chain | 文档列出 sweep、safety、public evidence、report 和 exact-grid sidecar 的 ID/manifest/hash，以及当时 12 点成功的记录。 | **场景适配**，且本轮仅核对索引与 reader/测试，未重读本地不存在的原始 artifact。 |

## 历史路线图与当前状态

[#18](https://github.com/GNYKCZ/secure_pid_hvac/issues/18) 是历史路线图，不是本页的验收来源。它仍将
#17 显示为未勾选且把最终对照列为 future work；实际 GitHub 状态是
[#17](https://github.com/GNYKCZ/secure_pid_hvac/issues/17) 已关闭，
[PR #63](https://github.com/GNYKCZ/secure_pid_hvac/pull/63) 已在 2026-09-22 合入
`48d6e34f711473873a5e0cd0613bafb62a5db15a`。本页据 `origin/main` 的实际代码和 Issue #65
确定边界，不倒改历史路线图，也不把这一不一致视为论文复现证据。

## 后继 Issue 的 claim gate

| 消费者 | 可直接采用 | 必须自行完成，不能从本页继承 |
| --- | --- | --- |
| A05/#69 | 论文/当前实现的机制定位、四级声明、四水箱缺口和 [39] 参数账本 | four-tank 场景、plant/observer 公式的源码级核验、测试和原例证据 |
| A06/#70 | PID Fig. 3 参数、精度文字冲突、`t=0..50` 与 claim boundary | [38] plant、filtered PID、唯一 `q`/seed 的可得性、运行和轨迹对比 |
| A09/#73 | Protocol 2 的前提与 `w in {-1,0,1}`、当前 integer A/B 限制 | 任何非整数 controller 的 end-to-end 资源/误差证据 |
| A11/#75 | Assumption 2/3 的论文含义与当前 HVAC/transport 非等价边界 | 对目标 plant/controller 的完整闭环证明和部署级安全声明 |

## 自审记录

- 已逐项核对论文 v3 §II Eq. (2)–(4)、§III Eq. (5)–(6)、Definition 1、Protocols 1–3、
  Eqs. (9)–(15)、Assumptions 2–3 与 §VII/Figs. 3–4。
- 已核对 `ControllerSpec`、fixed-point/share/Beaver/Trunc/Protocol 3、HVAC PID/plant、
  sweep 配置、相关 tests 和已提交 evidence index；没有修改它们。
- 本页没有新增 public API、配置字段、角色可见数据或依赖方向。它不提供生产安全、原例数值、
  性能或原始 artifact 的未验证声明。
