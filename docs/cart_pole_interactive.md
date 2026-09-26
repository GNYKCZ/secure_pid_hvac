# 倒立摆动画 Client：三角色快速操作

这是近直立、有限步仿真。默认初态约为 5°，每个控制区间对应 **20 ms 仿真时间**；窗口帧率及网络墙钟时间不保证 20 ms。真实三电脑、TLS 身份/加密和硬实时能力尚未实测。

## 本机三终端

在相同仓库和 `uv.lock` 环境中，依次开三个终端：

```powershell
uv run python scripts/run_continuous_p1.py
uv run python scripts/run_continuous_p2.py
uv run python scripts/run_cart_pole_client.py
```

也可在 VS Code 中直接对 `scripts/run_cart_pole_client.py` 使用“运行 Python 文件”，无需修改脚本。窗口先显示初态/待连接，随后按实际 Client 阶段显示连接中、双方已连接、运行中、普通支重放、验证/保存及完成或失败。P1/P2 的 `closed` 不单独表示 Client 成功。

运行中按左/右方向键或点击按钮，请求 −1/+1 N 的水平小车外力，持续**一个控制区间**，等效冲量 ±0.02 N·s。点击仅表示排队；Client 在安全控制步双提交、控制器力裁剪后、plant 前锁存，实际步号由正式证据记录。队列满、取消或合力超出 ±10 N 时拒绝；不会悄悄裁剪外力。状态的 `recovering/stable` 沿用 #91 的四维观测判据。若越工作域、失稳、断连或关窗，运行失败且不能把未验证结果称为成功；重试需重启三个角色以取得新 session/材料。

完成后滑块从已验证的 `cart_pole_evidence.json` 重看第 0…400 个观测，显示位置、角度、上一区间控制器 **applied** 力、外力以及 ideal−secure 位置差。按钮打开同一 run 的 `control.png` 与 `cart_pole_motion.png`。正式 `trajectory.csv` 的 control 仍只含控制器 applied 力，外力在 v2 侧证据逐步单列。`metadata.json` 摘要绑定两图及侧证据；仅通过专用 verified reader 的结果可回放。默认输出在 `results/lan_continuous/<run-id>/`。

## 三电脑配置

三台电脑使用同一代码和锁文件，将 `configs/local-deployment.example.yaml` 的三条地址与固定端口改成可互访的机器地址，并在三台上保持内容一致；P1/P2 分别运行现有脚本，Client 以自己的一份角色配置路径运行 `uv run python scripts/run_cart_pole_client.py <client-config>`。Client 配置指向本机可读的倒立摆 experiment profile；各角色的 topology、传输模式和证书设置必须与现有 [LAN 说明](lan_continuous.md)一致。示例 `insecure_tcp` 只适合可信隔离实验网，**没有身份认证或传输加密**；需要认证时使用项目已有 mTLS 配置。本 Issue 未在真实三台电脑上验证连接、身份或延迟，不能把本机三进程运行视作三机验收。
