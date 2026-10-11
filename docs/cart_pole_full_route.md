# 下垂起点两测量完整路线（Issue #103）

[设计评论](https://github.com/GNYKCZ/secure_pid_hvac/issues/103#issuecomment-5864293877)与[用户批准的安全边界](https://github.com/GNYKCZ/secure_pid_hvac/issues/103#issuecomment-5865358983)是本路线依据。原 #102 静态起摆入口、近直立动态入口及其 v1/v2 结果保持各自语义。

从仓库根目录运行明文完整路线，无需 P1/P2：

```powershell
uv run python scripts/run_cart_pole_client.py --full-route plaintext --full-output results/diagnostics/plain-full-v3
```

安全路线先在另两个终端运行 `uv run python scripts/run_continuous_p1.py` 和 `uv run python scripts/run_continuous_p2.py`，再运行：

```powershell
uv run python scripts/run_cart_pole_client.py --full-route secure --full-output results/diagnostics/secure-full-v4 --segment-steps 100
```

窗口入口将 `--full-route` 换为 `--full-gui-route`。`--full-output` 必须是尚不存在的目录；已验证的 `run.json`、`physical.json` 和 `steps.jsonl` 才会发布。输出含终止原因、`goal_met` 和真实完成步数；未达目标的运行返回非零退出码。`--swing-config`、`--observer-config`、`--prime-config` 可指定合法参数源。默认安全路由复用 Client LAN 角色配置和已认证 256 位素数；`insecure_tcp` 只适合可信隔离网络，不提供身份认证或加密。

两条路线各自从声明的下垂初态独立推进 canonical plant。控制只读取 `p` 与连续 `theta` 两测量：k=0 速度种子为零，k=1 一阶后差，其后用因果三点后差。捕获时显式建立新的四维动态 observer；重入会结束旧 epoch 并建立新 epoch。仿真真值仅进入诊断。P1/P2 的固定门计算起摆力，Client 公开判定阶段和安全事件；阶段时间与切换次数因此对双方可见。单个 party 只收到测量、系数和 observer 状态自己的份额。公开 kick 也走双方输出份额路径。

安全起摆使用固定 38 个 Beaver 乘法/Protocol 2 截断门，`ell=80`、`lambda=80`；全声明输入盒的整数/有理界在连接前验证。进入动态捕获后使用原有四维秘密 observer、`ell=32`，逻辑段续跑保持同一秘密状态；跨阶段切换必须等双方结束回执。每个物理区间记录来源、raw/applied/外扰、epoch、轮次、资源身份和物理确认。v3 reader 重放因果观测、阶段、独立理想控制和 canonical plant，并核对双方关闭前缀、资源唯一性、数值精度与配置派生门拓扑。结果摘要用于完整性检查，不提供恶意参与方安全认证。

数值证书覆盖允许输入盒内的算术误差，不声称整个盒子都物理可行；边界状态仍可能在任何允许力下越轨。当前验收是本机三进程仿真，不代表真三机、真实设备、20 ms 墙钟实时、恶意方安全或全局稳定性。

## #120 P0：完整安全路线的非实时基线观察

以下入口调用同一个 `run_secure_full_experiment`，使用 canonical 配置及原安全材料/计算/提交顺序，不发布正式 v3 产物，也不启用新的周期保护：

```powershell
uv run secure-control benchmark --case full-observation --steps 1500 --segment-steps 400 --delay-ms 0 --output .tmp/full-baseline.json
```

默认 `--mode batch`，本入口不支持 legacy、动态预送或 `--diagnostic`。默认启动测试拥有的回环 P1/P2；指定 `--role-config` 时仅运行 Client，使用现有外部角色，不自行部署。此时注入等待只施加在 Client 的应用发送，P1/P2 内部没有观测数据。每应用 send 前的等待不是链路 RTT；失败 send 的帧/字节计数是尝试值，不能当完整传输事实。

步数上限1500，段上限1000；原 acquisition 与 horizon 等合法约束仍成立，不能仅缩短 horizon 就放宽证明或控制参数。观察最多1501个测量消费记录、256个生命周期事件，每步编码细节上限4KiB；溢出明确计数。只输出公开阶段、身份、时刻、时长、资源计数、流量和环境/源码摘要，不输出测量值、份额、材料、控制数值、秘密状态或异常原文。采集有开销，wall含等待；嵌套分项不能相加当纯CPU。

原路线初始及每步尾部会提前读取下一测量。报告分开保存读取/消费时刻和测量年龄，完成步的时长是“消费到已确认回调结束”，含该步内真实 epoch 结束/重建及段维护；终点观察和失败单列，失败时长不伪填0或20ms。初次准备单列，首步不剔除。kick/energy/dynamic分别统计；过程已有设备回执的事实不因之后失败抹掉。`qualification_pass`恒false，无绝对计划时钟或调度启动偏差，超过20ms的耗时统计不等于正式 deadline 资格。

P0只是测量基线；软件阶段完成不能自动关闭#120，缺三机/认证/硬件和长期资格时继续明确未验证。

## #120 P1：完整路线周期与v4结果

正式安全完整CLI/GUI默认启用plant配置的绝对周期（当前20ms）。初次固定证明/配置/认证/kick装配先完成并单列耗时，然后只建立一次t0。每个全路线物理步k在t0+kT到达后新读两测量；不使用上步提前预读作为本次采样，不按epoch重置或跳步。阶段结束、新x0数值证明、重新连接/装配、材料/运算/双提交、设备回执、记录/观察回调都使用同一截止。满动态段的end/begin属于产生满段的周期尾部；最后stop/close单独报告，不捏造下一周期。输入相关捕获证明仍完整执行，慢机器会诚实停止；保护不是速度改善。

`run_secure_full_experiment(..., realtime=False)`保留旧API非实时诊断；命令需显式`--full-non-realtime`，可用于安全完整CLI或GUI。此模式写旧v3且无20ms资格。明文入口仍按原语义写v3。P0观察明确调用非实时路径，其旧SHA/报告不能当新路径性能。

实时安全结果使用同一个writer/verified reader的v4：原三文件加`timing.jsonl`（CycleTiming v1），绑定全部尝试、初始准备/终止耗时、源代码及配置hash、代码SHA/dirty、公开epoch链与摘要。收集最多1500个周期；reader限制每行4KiB/文件16MiB并严格重放原数学和plant，不新增依赖或放宽v3。源码hash代表当次实际来源，Git head单独记录；hash完整性不是恶意参与方身份认证。

协议双提交、设备积分完成、周期出口、双方密封和当时磁盘可靠前缀是独立事实。设备前已知过期不发新控制；已确认设备动作后超期记`miss_after_apply`，保留实际确认数和可验证轨迹，不回滚、不发送下一步。仿真回执仍不是硬件实际施力；检查不能抢占在途CPU/命令，真实设备期限与保护依赖#110。无法确认双方提交时记uncertain，烧毁本轮材料，不重连恢复或重试。

`cycle_failure`记录当前周期失败；`finalization_failure`单列停止密封失败；未达到的时间端点为null。最后一步已确认但超期不虚构第k+1个物理失败区间。`on_cycle`只收到未完成的`observing`快照，其成本也计入预算；**最终事实以返回结果的cycles为准**，回调收到的快照不能作为周期PASS。在最后写盘前所有durable_step_count保持0，不把保存成功倒填进实时记录。分项时长可能嵌套，不能相加当独占CPU。

writer仅发布真实双方密封的物理前缀；timing可包含之后未密封/失败的尝试，它们不成为verified物理轨迹。没有正长度密封前缀时，不强造结果目录：CLI输出公开失败/计数及`no_sealed_prefix`，GUI保留已确认动作数并显示无可验证回放。旧v3继续严格读取，明确未提供周期证据。v4存在也不自动说明全路线、真实三机或长期零超期通过。

## #120 P2：固定精确计算复用

正式完整路线在t0前按实际编码observer矩阵准备到首次收缩的固定候选。原有符号Fraction矩阵幂、绝对幂和、求逆与向上取整公式保持；捕获时仍代入当次x0、B、输入盒与误差，按原顺序选block，Client再次执行全部数值门禁。更高候选未命中时现场完整计算，成本仍在本次截止内。

缓存只属于当前控制线程的一次运行，退出立即释放；不可变tuple/Fraction，最多128项、保守Python对象收费上限4MiB，容量不足只导致逐出或重算。不保存状态界结论、秘密份额或随机材料，不公开矩阵key或参数摘要。v4仅保存容量、收费、命中/逐出和启动准备耗时。首次固定收缩的block不等于完整状态界最终采用的block。

非实时观察默认关闭复用；同一配置对照时显式加`--fixed-proof-cache`。两种观察仍无正式deadline资格。固定准备减少重复计算的收益必须连同装配、首个动态步和完整周期实测；不能据缓存命中或功能测试宣布20ms达标。
