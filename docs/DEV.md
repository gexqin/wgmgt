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
│   ├── cli/            # cobra 命令树:root / version / doctor
│   └── wgkern/         # 内核 WireGuard 检测(纯检测,无副作用管理)
└── docs/               # 本文档
```

分层原则:`cli` 层只做参数解析与输出格式化,业务逻辑放 `internal/*`
领域包中,保证逻辑可单测(命令处理函数不写测试,领域包写)。

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
