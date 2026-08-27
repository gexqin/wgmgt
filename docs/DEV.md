# WGMGT 开发文档

## 环境要求

- Go ≥ 1.27(本机装在 `~/.local/go1.27`,不在 PATH 时:
  `export PATH=$HOME/.local/go1.27/bin:$PATH`)
- Linux + 内核 WireGuard(开发机用 WSL2 即可;`wgmgt doctor` 验证)
- git

## 常用命令

```sh
go build ./...              # 编译所有包
go build -o wgmgt ./cmd/wgmgt   # 产出二进制
go vet ./...                # 静态检查
go test ./...               # 单元测试
go test -race ./...         # 竞态检测(CI 用)
```

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
│   ├── app/            # CLI 与 Web 共享的编排:SyncConf、NextFreeIP
│   ├── cli/            # cobra 命令树:init/up/down/peer/status/web/doctor/version
│   ├── confgen/        # wg-quick 兼容 conf 渲染(服务端 + 客户端)
│   ├── humanize/       # 时长/字节的人类可读格式化
│   ├── store/          # SQLite 存储(modernc.org/sqlite,纯 Go 无 CGO)
│   ├── web/            # 内嵌 Web UI(go:embed 模板+静态资源,token 鉴权)
│   ├── wgctl/          # netlink 应用层:up/down/热应用/状态读取
│   └── wgkern/         # 内核 WireGuard 检测
└── docs/               # 本文档
```

分层原则:`cli`/`web` 层只做参数/请求解析与呈现,业务逻辑放
`internal/*` 领域包中,保证可单测(命令处理函数不写测试,领域包写)。

## Web UI 要点

- **鉴权模型**:随机 token 嵌入 URL 前缀(`/t/<token>/`),错 token
  一律 404。没有 cookie/登录页——令牌即 URL,泄露 URL 即泄露权限。
- **模板**:每个页面 clone base 后独立解析(stdlib `html/template`),
  peers 片段单独解析供 htmx 轮询端点复用。
- **htmx 只做一件事**:peer 表每 5 秒轮询刷新;操作(up/down/表单)
  都是普通 POST + 303,无 JS 也能用。

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
