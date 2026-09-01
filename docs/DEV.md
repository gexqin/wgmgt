# WGMGT 开发文档

## 环境要求

- Go ≥ 1.27(本机装在 `~/.local/go1.27`,不在 PATH 时:
  `export PATH=$HOME/.local/go1.27/bin:$PATH`)
- Linux + 内核 WireGuard(开发机用 WSL2 即可;`wgmgt doctor` 验证)
- git

## 常用命令

```sh
go build ./...              # 编译所有包
go vet ./...                # 静态检查
go test ./...               # 单元测试
go test -race ./...         # 竞态检测(CI 用)
```

发布/部署用二进制(静态、注入版本号,产物名固定 `wgmgt`):

```sh
CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w \
    -X github.com/gexqin/wgmgt/internal/cli.version=$(git describe --tags --always) \
    -X github.com/gexqin/wgmgt/internal/cli.commit=$(git rev-parse --short HEAD)" \
  -o wgmgt ./cmd/wgmgt
./wgmgt version             # 验证:wgmgt v0.1.0 (5ecca4c) linux/amd64
```

版本号基线:**v0.1.0 = M3 完成**(单机 CLI/Web/多节点主控+agent 全部可用)。
`git describe --tags` 自动产出 `v0.1.0` / `v0.1.0-3-g1a2b3c4` 式版本串,
M5 的语义化版本流程直接沿用此机制。

交叉编译(M4 会做成发布矩阵):

```sh
GOOS=linux GOARCH=arm64 go build -o wgmgt-linux-arm64 ./cmd/wgmgt
GOOS=linux GOARCH=arm   go build -o wgmgt-linux-armv7 ./cmd/wgmgt
```

## 目录结构

```
wgmgt/
├── cmd/wgmgt/          # main 入口,只做 cli.Execute()
├── internal/
│   ├── agent/          # agent:pull 循环、配置收敛(netlink)、状态上报
│   ├── app/            # CLI 与 Web 共享的编排:SyncConf、NextFreeIP
│   ├── certs/          # 内置 PKI:CA / 服务端证书 / agent 客户端证书
│   ├── cli/            # cobra 命令树:init/up/down/peer/status/web/server/agent/doctor/version
│   ├── confgen/        # wg-quick 兼容 conf 渲染(服务端 + 客户端)
│   ├── control/        # 控制端:mTLS poll API、配置下发、状态上报缓存
│   ├── humanize/       # 时长/字节的人类可读格式化
│   ├── store/          # SQLite 存储(多节点:interfaces 按 (node,name) 主键)
│   ├── web/            # 内嵌 Web UI(go:embed;本地/控制台双模式)
│   ├── wgctl/          # netlink 应用层:up/down/热应用/状态读取
│   └── wgkern/         # 内核 WireGuard 检测
└── docs/               # 本文档
```

分层原则:`cli`/`web` 层只做参数/请求解析与呈现,业务逻辑放
`internal/*` 领域包中,保证可单测(命令处理函数不写测试,领域包写)。

## 控制端 / agent 要点(M3)

- **协议**:POST /api/poll,JSON over mTLS,**HTTP 长轮询**。agent 的
  证书 CN 即节点名;请求体带 `since`(已应用的配置版本)+ 实时状态。
  `since` 等于当前版本时服务端挂起至多 `--poll-hold`(默认 25s,0 关闭),
  直到版本变化(store 变更钩子经 Notifier 即时唤醒)、hold 到期或客户端
  断开;版本**不同**时(注意不是"更新"——删除接口会使版本**下降**)
  响应携带完整期望配置,否则只回版本号(几百字节)。agent 每轮完成即
  立即重发(请求本身就是定时器),失败按 `--interval` 退避;状态随每轮
  长轮询上报,节奏 ≈ hold。进程外直改 DB 不触发钩子,一个 hold 周期内
  自愈。
- **配置版本**:`interfaces.config_version` 每次变更 +1,节点版本取其
  接口的最大值。agent 只在版本变化时重新应用(避免重置 peer
  流量计数器)。
- **agent 无状态**:唯一本地痕迹是 conf 目录(也作为"受管接口集合"
  的记录,重启后据此上报状态)。
- **期望态模型**:控制台的 Enable/Disable 写 `enabled` 列并 bump 版本,
  agent 收敛(enabled→确保 up;disabled→删设备)。
- **热更 vs 重建**:agent 按"路由签名"(地址/端口/MTU/是否含默认路由)
  决定——签名不变只热更 peer(不断线);变了就重建设备。这也是全隧道
  开关能生效的机制。

## Token 引导注册(2026-09-01 补)

- **`enroll_tokens` 表**:只存 token 的 sha256;三个时间列(created/
  expires/used)一律 Go 侧写 RFC3339 UTC——库里其它表的
  `datetime('now')` 默认值与 RFC3339 字符串**字典序不兼容**。兑换用
  单条 `UPDATE ... WHERE used_at = '' AND expires_at > now` +
  RowsAffected 判定(单连接 SQLite 即原子);未知/过期/已用统一
  `ErrNotFound`,对外不可区分。过期行在创建新 token 时懒清理。
- **TLS 层 `VerifyClientCertIfGiven`**(而非 RequireAndVerify):
  引导请求(`/api/enroll`)没有客户端证书,认证靠 token;`handlePoll`
  自己在 handler 层拒绝无证书请求(401)。服务端出示链**尾部追加
  根 CA 的 DER**——否则 agent 的 `--ca-hash` pin 无从比对。
- **烧毁顺序**(fail-closed):先做廉价的公钥形状校验(坏请求不浪费
  token)→ 烧毁 token → 签证书。签发失败时 token 已烧,节点须重铸。
- **`EnsureNodePending` vs `EnsureNode`**:预注册 pending 节点必须用
  前者(`ON CONFLICT DO NOTHING`);后者 upsert fingerprint,会把已
  注册节点的指纹抹掉、破坏吊销。pending 节点 fingerprint 为空时
  poll 放行任意本 CA 签的同 CN 证书——可接受,因为只有控制端 CA
  能签发。
- **agent 侧**(internal/agent/enroll.go):本地生成 P-256 密钥,只发
  公钥(PKIX PEM);`InsecureSkipVerify` + `VerifyPeerCertificate`
  回调实现 pin(链中任一证书哈希 == pin,且叶子对该根做完整 Verify
  含主机名校验)。该 client 用**硬超时 30s**——注册没有长轮询,别抄
  poll client 的无超时模式。响应材料二次校验(pair 一致 + 证书由
  返回的 CA 签发),落盘 conf-dir(0700,key 0600);重启时
  `LoadMaterial` 命中即跳过注册。

## 全隧道与自锁回退(2026-08-27 补)

- **策略路由**(wgctl):AllowedIPs 含 0/0 或 ::/0 时,wg-quick 同款
  三件套——设备 fwmark(=表号)、默认路由进 table 51820、两条 rule
  (`not fwmark → 51820` @32765,`main suppress_prefixlength 0` @32764)。
  Down 时必须显式删 rule(路由随设备消失,rules 不会)。
- **验证式看门狗**(agent):应用新配置 → 下一轮成功 poll 即验证;
  `--verify-timeout`(默认 180s)内未验证 → teardown 全部受管接口 +
  隔离(该版本不再重试,直到更新的版本)。已验证配置不受控制端
  后续故障影响(不会误伤)。
- **两个用血泪换来的实现细节**:
  1. agent 的 HTTP client 不能用整体硬超时(会杀掉长轮询的 held 响应),
     但连接阶段必须有硬超时——黑洞里的 TCP connect 会挂死在 SYN 重传
     上,卡住整个 Run 循环,看门狗就永远不会被调度。正解是 transport
     级:DialContext/TLSHandshakeTimeout 各 10s(锁死节点 ~10s 内失败),
     ResponseHeaderTimeout 60s 兜底沉默的控制端(服务端 `--poll-hold`
     必须小于它);
  2. 热更 peer 不会重装路由——0/0 加入时若只 ApplyPeers,策略路由
     根本不生效(不会锁,但也"不会生效")。签名比对才是正解。

## 端到端回归(单机)

M3 基础:
```
server enroll n1/n2 → server 起 --api 192.0.2.1:8443
agent n1(根 ns) + agent n2(netns wgc,经 veth)
控制台表单:n1 建 wgA、n2 建 wgB → 交叉 peer → ping 通;远程启停收敛
```

全隧道自锁回退(三 netns:ctrl / node,node 仅默认路由可达 ctrl 的
网段外地址 10.9.9.9):
```
node 起 agent(--verify-timeout 12s)→ 正常接口 v1 ✓
投毒:0/0 假 peer → v2 → 自锁(rules/table 装上,poll no route to host)
12s 后回退(rules 清、设备删、连通恢复)+ ⚠ QUARANTINED 徽章
删毒 peer → v3 → 自动重应用 → ● ONLINE
```

## Web UI 要点

- **鉴权模型**:随机 token 嵌入 URL 前缀(`/t/<token>/`),错 token
  一律 404。没有 cookie/登录页——令牌即 URL,泄露 URL 即泄露权限。
- **模板**:每个页面 clone base 后独立解析(stdlib `html/template`),
  peers 片段单独解析供 htmx 轮询端点复用。
- **htmx 只做一件事**:peer 表每 5 秒轮询刷新;操作(up/down/表单)
  都是普通 POST + 303,无 JS 也能用。
- **一次性展示页**(控制端 Add node):join 命令存进程内 map(随机
  id → 命令),GET `/enroll/{id}` 弹出即删,二次访问 404。token 本身
  一次性,页面同样一次性只是纵深防御。

## 关键实现事实

- **SQLite 驱动是 modernc.org/sqlite(纯 Go)**,不是 mattn/go-sqlite3:
  保持 CGO-free,交叉编译到梅林/OpenWrt(musl/arm)才能零成本。
  代价是二进制约 13MB。
- **单连接串行化**:`db.SetMaxOpenConns(1)` 规避 SQLITE_BUSY,
  modernc 驱动不支持并发写。
- **up 是原生 netlink**(`vishvananda/netlink` 建链路/地址/路由 +
  `wgctrl` 下发 WG 配置),不 shell 出 wg-quick——路由器上没有
  wireguard-tools 也能用。
- **默认路由跳过**:allowed IP 为 0.0.0.0/0 时只告警不加路由,
  策略路由(fwmark/Table)是 M1 之后的议题。

## 回归测试:本机端到端

不依赖第二台机器,用 netns + veth 模拟客户端,M1 即用此法验证过
握手与数据面:

```sh
T=/tmp/e2e; W=./wgmgt
$W --db $T/db --conf-dir $T init --name wgS --address 10.99.0.1/24 --port 51899
$W --db $T/db --conf-dir $T init --name wgC --address 10.99.0.5/24 --port 51900
# 从 init 输出抓两个公钥,交叉 peer add(--public-key 导入)
# veth: 192.0.2.1/30 (root ns) ↔ 192.0.2.2/30 (netns wgc)
sudo $W --db $T/db --conf-dir $T up wgS
sudo ip netns exec wgc $W --db $T/db --conf-dir $T up wgC
sudo ip netns exec wgc ping -c3 10.99.0.1     # 期望 0% loss
sudo $W --db $T/db --conf-dir $T status wgS   # 期望 handshake + rx/tx
```

netlink 是 per-netns 的,所以 `ip netns exec` 里跑 `up` 会把链路建在
那个命名空间里——这也顺带验证了 netns 感知正确性。

## 关键设计决策

### 1. doctor 检测:自写 genl 探测,不用 wgctrl

`wgctrl.New()` 失败后会回退到 userspace UAPI 客户端——在跑 wireguard-go
的机器上会**误报**"内核兼容",违背本项目"内核 only"的硬约束。因此
`internal/wgkern/genl.go` 手写 generic-netlink family 解析(约 60 行),
语义精确:family "wireguard" 应答 ⇔ 内核模块可用。

### 2. 检测顺序与副作用

`Detect()` 的探测顺序(`detect.go`):

1. `/proc/modules` — 已加载 → AVAILABLE
2. `modules.builtin` — 内建 → AVAILABLE
3. `modules.dep` — 可加载未加载 → LOADABLE(提示 `sudo modprobe wireguard`)
4. genl netlink 探测 — family 应答 → AVAILABLE(终极判定)

**已知副作用**:第 4 步的 family 解析会触发内核 `request_module`
自动 modprobe(已实测验证)。这是良性的——检测完模块顺便就加载了。

### 3. module 路径

`github.com/gexqin/wgmgt`,内部包 import 全部用完整路径。

## 代码约定

- 标准 Go 风格(`gofmt`/`go vet` 必须干净);注释用英文(开源受众)
- 错误处理:领域包返回 `error`,CLI 层用 cobra `RunE` 透出,退出码非 0 即失败
- 用户可见输出走 `cmd.OutOrStdout()`,便于测试捕获
- 提交信息:英文,首行祈使句,里程碑前缀(如 `M0: ...`、`M1: ...`)

## 风险清单(随开发验证)

| 风险 | 影响 | 计划 |
|------|------|------|
| 梅林固件 musl libc 兼容性 | 静态二进制理论免疫,需实测 | M4 |
| OpenWrt 各架构内核 WG 检测路径差异 | doctor 的文件探测可能需适配 | M4 |
| wgctrl 在老内核上的 netlink 兼容 | M1 引入时验证 | M1 |
| WSL2 内核 WG 行为与真机差异 | 开发环境仅供参考 | 持续 |
