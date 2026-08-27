# WGMGT 使用说明

> 当前版本:**M1**——单机 CLI 闭环(接口/peer/密钥/conf/上下线/状态)。
> 完整路线图见 [PLAN.md](PLAN.md)。本文档只描述**已实现**的功能。

## 安装

从源码构建(需要 Go ≥ 1.27):

```sh
git clone https://github.com/gexqin/wgmgt
cd wgmgt
go build -o wgmgt ./cmd/wgmgt
sudo cp wgmgt /usr/local/bin/   # 可选,放进 PATH
```

## 兼容性前提

WGMGT **只使用内核 WireGuard**,不内置任何用户态实现。运行前先跑
`wgmgt doctor` 确认(详见下文)。

## 概念模型

- **SQLite 是唯一真相**:所有接口、peer、密钥都存在
  `/etc/wireguard/wgmgt/wgmgt.db`(权限 0600,含私钥)。
- **conf 文件是生成产物**:`/etc/wireguard/wgmgt/<接口名>.conf`,
  wg-quick 兼容,每次变更自动重新生成,可直接交给 wg-quick 用。
- **原生 netlink 应用**:`wgmgt up` 不调用 wg-quick 脚本,直接通过
  netlink 创建链路、配地址、下发配置、加路由——路由器上无需
  wireguard-tools。

## 快速上手

```sh
sudo wgmgt init                          # 向导式创建接口(地址/端口有默认值)
sudo wgmgt peer add --name laptop \
    --server-endpoint vpn.example.com:51820   # 生成密钥,打印客户端 conf
sudo wgmgt up                            # 拉起接口
sudo wgmgt status                        # 查看握手与流量
```

把 `peer add` 打印的客户端 conf 保存为 laptop 上的配置,导入任意
WireGuard 客户端即可连接。

## 命令详解

所有命令支持 `--db` / `--conf-dir` 覆盖默认路径(测试或多实例)。
仅管理一个接口时,`[interface]` 参数可省略。

### `wgmgt doctor`

检测内核 WireGuard 支持,退出码 0 = 兼容,1 = 不兼容。

### `wgmgt init [flags]`

创建接口。非交互环境直接用 flags;交互终端会逐项询问(括号内为默认值):

| Flag | 默认 | 说明 |
|------|------|------|
| `--name` | `wg0` | 接口名(≤15 字符) |
| `--address` | `10.0.0.1/24` | 隧道地址(CIDR) |
| `--port` | `51820` | UDP 监听端口 |
| `--mtu` | 内核默认 | |
| `--dns` | 无 | 下发给客户端的 DNS |

### `wgmgt up|down [interface]`(需 root)

`up`:创建链路 → 配地址 → 下发 WG 配置(含全部 peer)→ 加路由。
peer 的 allowed IP 若不在隧道网段内会自动加路由;默认路由(0.0.0.0/0)
会跳过并告警(策略路由暂不支持)。
`down`:执行 PostDown(若有)后删除设备,地址路由随之消失。

### `wgmgt peer add [interface] --name <标签> [flags]`

生成新密钥对并注册 peer,**打印客户端 conf**。接口运行中时热生效,无需重启:

| Flag | 说明 |
|------|------|
| `--allowed-ips` | 缺省自动在隧道网段分配下一个空闲 /32(仅 IPv4) |
| `--endpoint` | peer 的公网地址(漫游型客户端可省略) |
| `--keepalive` | PersistentKeepalive 秒数(NAT 后客户端建议 25) |
| `--preshared-key` | 额外生成 PSK(增强抗量子安全性) |
| `--server-endpoint` | 本机公网地址,存库供客户端 conf 使用 |
| `--public-key <key>` | **导入模式**:peer 自管密钥(客户端自己 `wg genkey`),不生成客户端 conf |
| `--output <file>` | 客户端 conf 写入文件(0600)而不是打印 |

### `wgmgt peer list [interface]`

peer 表格;接口运行中时附实时握手时间 / 收发流量。

### `wgmgt peer rm <interface> <peer>`

按名称、公钥或 ID 删除;运行中热生效。

### `wgmgt peer conf <interface> <peer>`

重新打印 peer 的客户端 conf(客户端私钥存在库里,随时可重取;
这也是把客户端私钥存在服务端的代价与收益,介意者用 `--public-key` 导入模式)。

### `wgmgt status [interface]`

接口状态(up/down、地址、端口)+ 运行中每个 peer 的握手时长与流量。

## 验证过的端到端测试

开发中用 netns + veth 对在本机模拟了完整的客户端-服务器握手与数据面
(见 [DEV.md](DEV.md) 的回归测试一节)。

## 后续版本预告(未实现)

- `wgmgt web` — 内嵌 Web UI(HTMX)(M2)
- `wgmgt server / wgmgt agent` — 多节点集中管理(M3)
