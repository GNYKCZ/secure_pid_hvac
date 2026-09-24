# #70 paper-inspired PID Fig. 3 方法与阈值对照

本实验依据 [设计定稿](https://github.com/GNYKCZ/secure_pid_hvac/issues/70#issuecomment-5798124932)，
沿用 [#69 明文对象](paper_pid_baseline.md)：论文 arXiv:2503.02176v3 §VII 的印刷 PID，
以及从 [38] Eq. (2) 派生、由本仓库选择逐级输出状态坐标并以 0.1 s ZOH 离散化的四级对象。
作者原离散 `A_p/B_p/C_p`、状态坐标、离散化细节和 Fig. 3 原始逐点数据未取得。
因此这里完成的是 **paper-inspired 方法/阈值对照**，不是作者原对象或 Fig. 3 的逐点复现。

## 来源、语义与运行

- [`configs/paper_pid_fig3_sweep.yaml`](../configs/paper_pid_fig3_sweep.yaml) 以 SHA-256 锁定
  #69 对象配置和仓库已验证的 256-bit Pocklington 素数证据；此 `q` 是本仓库选择，
  论文没有公布唯一 `q`。
- 固定 `ell=32/40/48/56`、论文参数位宽 `k=ell+8`、`lambda=80`、`x_p(0)=[100]×4`、
  `x_c(0)=[0,0]`、`k=0..50`。论文 §VII 数值句和 Fig. 3 图注支持该精度组；
  相邻正文另写 `32/40/58/64`，本实验显式保留该矛盾。
- `k=ell+8` 只约束参数和初态的编码资格。动态 state/input 使用 `ell+14` 位：
  在公开前提 `|y_k|≤128`、51 步下，两个控制状态的绝对 payload 上界由
  `51×(128×2^ell+1)` 给出，小于 `2^(ell+13)`。Client 在离线分享前逐精度验证
  state/output accumulator、Protocol 2 `κ` 和 centered `q/2`；在线每轮拒绝越界输入。
  这是有限时域条件证明，不是无限时域闭环不变集。实际两支 `|y|` 还必须通过运行后检查。
- v1 schema 强制 reference 通道；这里的 `unused_zero` 恒零且 adapter 完全忽略。
  两支各用独立 plant、adapter、runtime；控制输入就是本支更新前 `y(k)`，
  `raw u(k)` 在更新前 `x_c(k)` 上计算，恒等 actuator 使 `raw=applied`。
  `u/y` 的物理单位论文未给出，误差与 `u` 同单位。
- 每点共享参数和初态先离线分发；每步 Client 分享本支 `y`，P1/P2 执行通用
  Protocol 3，只有 Client 重构 `û` 并驱动安全 plant。单进程仅验证正确性；
  localhost 是三个本机进程，不代表认证 LAN 或生产部署安全。固定 `test_seed=70`
  只用于诊断重跑，不构成真实随机材料安全声明。

运行与复验：

```powershell
uv run python -m secure_control.experiments.paper_pid_fig3 --config configs/paper_pid_fig3_sweep.yaml --output-root results/paper_pid_fig3 --seed 70
uv run python -m secure_control.experiments.paper_pid_fig3 --verify-dir results/paper_pid_fig3
uv run python -m secure_control.experiments.paper_pid_fig3 --config configs/paper_pid_fig3_sweep.yaml --output-root results/paper_pid_fig3_localhost --seed 70 --backend localhost
```

每个点是 v1 成功目录，含 `trajectory.csv`、`config.json`、`metadata.json`，
由通用 reader 验证哈希、列、shape、逐点误差和状态。四点全部成功才发布
[`manifest.json`](../results/paper_pid_fig3/manifest.json) 和
[`fig3.png`](../results/paper_pid_fig3/fig3.png)。绘图入口仅读取这些已验证数据；
纵轴为 symlog，使真正的零值保持为零。正式四点原始数据随本 Issue 的 PR 版本管理，
因为它们正是本 Issue 要求审查和重建的证据；其余临时实验结果不提交。

## 实测结果

单进程固定 seed=70 的 51 点比较，`max |u−û|` 由正式 reader 从逐点 raw 控制量重算：

| ell | max `|u−û|` | `< 2^-10` | binary64 观测限制 |
| ---: | ---: | :---: | --- |
| 32 | `3.37553984763872e-08` | 是 | 曲线可见 |
| 40 | `1.0243184078717604e-10` | 是 | 曲线可见 |
| 48 | `2.2737367544323206e-13` | 是 | 部分点触及分辨率 |
| 56 | `1.1368683772161603e-13` | 是 | 部分点触及分辨率 |

此轨迹中 binary64 控制量局部间距的上界为 `5.684341886080802e-14`。
48/56 位曲线的部分点已落入浮点抵消/ULP 地板，不能据图判断真实的低位误差，
更不能据 51 点声称论文的无限时域阈值定理。若要求更细的曲线，需审查高精度
理想/plant 及 Client 解码审计路径，不能调对象或放宽阈值。

四个精度各自实耗 459 个逻辑 Beaver triple、102 组 Trunc 资源，均未按两方双计。
localhost 同配置完成四组 51 步，三个角色进程互异，资源计数同上；固定 seed 下
逐点安全控制量与单进程四组均一致。该结果只说明本机角色路径在此配置下通过。
