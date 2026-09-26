# 倒立摆动画 Client：三角色快速操作

默认窗口持续运行，点击“停止并保存”提交正常停止请求。段容量由
`--segment-steps 400` 指定（允许 1…1000），总步数由实际停止时的双方确认前缀决定，
不会在第 400 步自动结束。保留显式 `--finite` 的原 400 步有限窗口。
需要仅运行 #100 的无 GUI 后端时，可使用：
`uv run python scripts/run_cart_pole_client.py --headless-continuous --segment-steps 400`。
先分别启动原 P1/P2；它们会在同一次启动中服务后续段。Ctrl+C 请求正常停止，Client
返回双方确认的 `stopped` 与准确步数；这个 headless 入口不产生正式长轨迹结果。
`--finite` 与 `--headless-continuous` 互斥。生命周期 API、失败计数与回调见
[持续分段后端](lan_continuous.md#持续分段后端100)。

这是近直立仿真。默认初态约为 5°，每个控制区间对应 **20 ms 仿真时间**；窗口帧率及网络墙钟时间不保证 20 ms。真实三电脑和硬实时能力尚未实测。本机三进程回归包含明文 TCP 与 mTLS，不能替代真实三机验收。

## 本机三终端

在相同仓库和 `uv.lock` 环境中，依次开三个终端：

```powershell
uv run python scripts/run_continuous_p1.py
uv run python scripts/run_continuous_p2.py
uv run python scripts/run_cart_pole_client.py
```

也可在 VS Code 中直接对 `scripts/run_cart_pole_client.py` 使用“运行 Python 文件”，无需修改脚本。窗口先显示初态/待连接，随后按实际 Client 阶段显示连接中、双方已连接、运行中、普通支重放、验证/保存及完成或失败。P1/P2 的 `closed` 不单独表示 Client 成功。

运行中按左/右方向键或点击按钮，请求 −1/+1 N 的水平小车外力，持续**一个控制区间**，等效冲量 ±0.02 N·s。点击仅表示排队；Client 在安全控制步双提交、控制器力裁剪后、plant 前锁存，实际步号由正式证据记录。队列满、取消或合力超出 ±10 N 时拒绝；不会悄悄裁剪外力。状态的 `recovering/stable` 沿用 #91 的四维观测判据。若越工作域、失稳、断连或关窗，运行失败且不能把未验证结果称为成功；重试需重启三个角色以取得新 session/材料。

运行时“已提交”画面只来自协议和物理均确认的安全支。停止请求立即拒绝新外力，
在途区间沿原门禁完成；停止处理中保留最近确认画面，不预报最终 N。
关窗属于取消，不等同于正常停止。后端停止后，窗口显示独立对照重放、验证、绘图、
发布阶段；双方 `closed` 不足以显示完整完成。停止时 recovering 或 stable 都如实记录。

完成后窗口显示结果目录，滑块及整数跳转支持实际第 0…N 个观测。读取在后台执行，
旧跳转不会覆盖新选择，最多缓存两块；第 k>0 个观测的施力来自上一区间 g=k−1，
第 0 个观测不伪造控制力。按钮打开同一 run 的 `control.png` 与 `cart_pole_motion.png`。
两图是固定 2048 桶的首/末/min/max 概要，逐步原值始终保留在数据块及精确回放中。
默认输出在 `results/lan_continuous/<run-id>/`。

持续结果使用独立 `cart_pole_segmented_run` format v1：根 `run.json/config.json`、
有序摘要链 `segments.jsonl`、各段 `protocol.json`，以及 n>0 段的 canonical 八字段 v1
数据块和倒立摆 v3 侧证据。完整 reader 从唯一初态连续复核两支、事件、跨段 monitor、
身份/资源及双回执；最后 0 步 stop 段保留回执但没有空 CSV 或虚构 SimulationResult。
分段数据块的 scope 是 `segment_fragment`，单块成功不表示整个 run 完成。
正式根仅在 reader、两图和取消门禁均通过后原子发布；磁盘不足、源变化或任何处理失败
不会发布完整成功。摘要/回执是原 Client 来源信任下的一致性证据，不是签名证明。

```python
from secure_control.experiments.cart_pole_segmented_evidence import (
    open_verified_cart_pole_segmented_run,
)
run = open_verified_cart_pole_segmented_run("results/lan_continuous/<run-id>")
print(run.metadata["N"], run.observation_at(run.metadata["N"]))
for entry, record, evidence, protocol in run.iter_segments():
    # 流式消费当前块，勿收集为全 run 数组。
    print(entry["index"], entry["global_start"], entry["global_end"])
```

`--finite` 保留旧 v1/v2 证据、exact-N 和末端 stable 要求，仍从
`cart_pole_evidence.json` 回放 0…400。通用重绘命令也识别新的完整聚合根：
`uv run secure-control redraw --run-dir <run-dir> --output <new-control.png>`。
它先完整验证，再流式绘制概要，不启动安全协议。

## 三电脑配置

三台电脑使用同一代码和锁文件，将 `configs/local-deployment.example.yaml` 的三条地址与固定端口改成可互访的机器地址，并在三台上保持内容一致；P1/P2 分别运行现有脚本，Client 以自己的一份角色配置路径运行 `uv run python scripts/run_cart_pole_client.py <client-config>`。Client 配置指向本机可读的倒立摆 experiment profile；各角色的 topology、传输模式和证书设置必须与现有 [LAN 说明](lan_continuous.md)一致。示例 `insecure_tcp` 只适合可信隔离实验网，**没有身份认证或传输加密**；需要认证时使用项目已有 mTLS 配置。本 Issue 未在真实三台电脑上验证连接、身份或延迟，不能把本机三进程运行视作三机验收。
