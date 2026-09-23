# 三角色 LAN 单步试验（Issue #68）

本入口只做一次 `k=0` 的研究试验，不是长期控制、生产级安全或执行器接口。
`Client`、`P1`、`P2` 是三个独立进程；Client 不生成或管理远端进程。通信方向固定为
Client→P1、Client→P2、P2→P1 peer，均强制 TLS 1.3 双向证书验证；不提供明文回退。
公开拓扑只有一份 `configs/lan-deployment.yaml`，三份角色配置都引用它。LAN 模式与原来仅
loopback、无 TLS 的本机后端并存，互不改变其接口或安全边界。

## 本机三个终端复现

安装 Python 3.11 和 uv，在项目根目录执行 `uv sync --locked`。本机示例的三份配置引用
`configs/local-deployment.example.yaml`，地址为 `127.0.0.1`，固定端口分别是
34401（P1/Client）、34402（P2/Client）、34403（P1/peer）。先在根目录准备**仅供本机测试**
的一天有效期角色证书；脚本拒绝覆盖非空目录，生成的目录由 `.gitignore` 排除，不要提交、
转发或在真实 LAN 复用这些私钥：

```powershell
uv run python scripts/prepare_local_lan_certs.py
```

在三个独立终端，按下列顺序各执行一行；P1、P2 会有界等待，最后启动 Client：

```powershell
# 终端 1
uv run secure-control p1 --config configs/local-p1.example.yaml
# 终端 2
uv run secure-control p2 --config configs/local-p2.example.yaml
# 终端 3
uv run secure-control client --config configs/local-client.example.yaml
```

预期 Client 输出一行 JSON，`status=complete`、`tls_version=TLSv1.3`、公开
`raw_control`、`baseline_raw_control`、差值、resource counts 和 `timings_ms`；P1/P2
各输出 `status=closed` 与不同的 PID。`raw_control` 是控制器更新前 raw 输出，不是执行器
限幅后的 applied control。当前冻结 HVAC 配置的第一步资源为 9 个乘法、0 个 Trunc；
真实数值以当次命令输出为准。一次成功或失败均退出，不会自动重试旧 session。

本机可复跑 `uv run pytest tests/test_lan_single_step.py -q`；该测试生成隔离短期证书与随机
固定测试端口，调用三个真实 `uv run secure-control ...` 进程，不替代真实三台主机验证。

## 三机配置、证书和安全边界

在三个主机各自安装相同 commit 与锁文件。复制并按现场网络修改
`configs/lan-deployment.yaml`，由受控渠道将**同一份字节内容**分发到三台机器。
`p1_client`/`p2_client`/`p1_peer` 的 `bind` 是监听机器已有的 IPv4 地址或 `0.0.0.0`；
`host` 是拨号方可解析、可路由的 DNS 名或 IPv4，`port` 是固定监听口。P1 开两个入站口，
P2 开一个入站口；Client 不开入站口。逐一检查三条方向的防火墙允许规则。没有发现、端口扫描、
NAT 穿透或自动开放防火墙功能。

每台主机在仓库**外**准备专用 CA trust file、该角色证书和私钥，修改对应
`configs/lan-{p1,p2,client}.yaml` 的本机路径。现场 CA 必须分别签发单一、精确 DNS SAN：
`client.secure-control.test`、`p1.secure-control.test`、`p2.secure-control.test`（或同步修改
topology 中的三个稳定身份名）；Client 证书有 clientAuth，P1/P2 因兼任 listener/dialer
需要 serverAuth 与 clientAuth，证书须在有效期内。私钥只留在所属主机，限制读取权限，
不能用本机教学 CA 作为现场信任根。`host` 作为 TCP 拨号地址，证书身份只按 topology 的
稳定角色 DNS SAN 验证；即使 `host` 是裸 IP 也不把该 IP 当成证书身份。证书、用途、SAN
或 topology digest 不符会终止会话。更换实体电脑时必须撤销旧机访问并更换该角色密钥；
本入口没有在线证书撤销服务，现场需要受控 CA/信任清单轮换。

现场启动命令（每台各执行一条）为：

```powershell
uv run secure-control p1 --config configs/lan-p1.yaml
uv run secure-control p2 --config configs/lan-p2.yaml
uv run secure-control client --config configs/lan-client.yaml
```

先 P1、P2，后 Client。三方配置、CA/证书/私钥、DNS/防火墙均应在启动前核对。退出码：
0 完整成功/关闭；2 配置缺项或本地路径不存在；3 解析、连接或监听错误；4 TLS 证书、身份、版本或协议
错误；5 等待、断线或提交/关闭不确定。失败输出只有角色、PID、类别和异常类型，没有 share、
随机量或原始帧。连接超时不能单凭发送端判定是路由还是防火墙丢弃：分别在拨号端核对解析与
路由、监听端核对 bind/端口和防火墙。固定端口占用属连接错误；证书身份错误属 4；
等待/中断属 5。旧 session 或提交不确定时废弃两方进程，重新试验须重新启动三方，
不能重发旧资源。试验参数沿用 `configs/hvac_dual_loop.yaml` 的研究用 `security_parameter=8`
和 61-bit 模数；TLS 不提升 MPC 参数强度。

## 同一新局域网的迁移清单

1. 获取新网络中 P1/P2 的可达地址或实际可解析名称，确认 Client→P1、Client→P2、P2→P1
   均可路由，确认三个固定端口、防火墙规则。
2. 在**唯一** topology profile 修改需要变化的 `host`、`bind` 或端口，受控分发完全相同
   的 profile；不要搜索替换源码，也不要把不同版本的 profile 混在三机。稳定 DNS 名称如仍
   正确解析可只更新 DNS；裸 IP 则须修改相应拨号地址。DHCP 地址变化本身不要求重新签发
   稳定角色 DNS SAN 证书。本机 `bind=0.0.0.0` 通常无需随接口 IP 变化。
3. 各机复查本机证书/私钥路径、CA、有效期和角色 SAN；换物理机则更换密钥并撤旧机权限。
   先 P1/P2 后 Client，完成一次新 session 的单步，逐项比对 raw 基线与公开耗时。
4. 保留三机各自 PID、主机/OS/Python/OpenSSL/commit、网络地址/固定端口、profile 摘要、
   证书公开角色、退出状态、Client `timings_ms` 与最大 raw 差值；不得保存私有 share、
   随机材料、私钥或原始应用帧。`trial_total` 含连接/证书开销，`step_end_to_end` 从生成
   在线输入至双提交确认；不要拿未同步的不同主机时钟相减。

当前仓库仅有本机独立进程和 loopback mTLS 自动验证；真实三台机器、第二局域网迁移、
现场抓包审计及现场时延都必须留待有设备后验证，不能由本机数字代替。论文原 PID/四水箱
数值复现、连续闭环和生产安全也不由本单步试验证明。
