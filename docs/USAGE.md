# WGMGT 使用说明

> 当前版本:**M3**——单机 CLI + Web UI + 主控/agent 多客户端集中管理。
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
| `--port` | `51820` | UDP 监听端口(`0` = 由内核随机分配临时端口) |
| `--mtu` | 内核默认 | |
| `--dns` | 无 | 下发给客户端的 DNS |
| `--san-dns` | 无 | 控制端服务器证书 SAN 的 DNS 名(逗号分隔;非交互环境下给出即执行 CA 设置步骤) |
| `--san-ip` | 无 | 控制端服务器证书 SAN 的 IP(逗号分隔) |

init 还会检查是否已有**非 wgmgt 管理**的 WireGuard 接口在运行(典型是
wg-quick 服务拉起的):有则列出并询问是否停止——留着会和 wgmgt 抢设备
和路由。选停止时,若接口由 `wg-quick@<名>.service` 提供,优先停服务
(让它自己清策略路由),否则直接删设备;非交互环境默认不停,仅告警。
注意停服务不等于禁用,重启后服务仍会拉起,需 `systemctl disable`。

若选的名字**已由 wgmgt 管理**(库里有旧配置),init 会显示其摘要并询问
是否**全量重置并重新初始化**(还有其他受管接口时会一并列出,一并删除)。
选是则:**先杀掉本机所有运行中的 wgmgt 进程**(server/agent/web——它们
内存里握着证书与库,不杀会继续用已删除的旧状态服务;若被 systemd/docker
自动拉起,会输出告警提示先停用该 unit)→ down 全部受管设备 → **整个
删除 `<conf-dir>/` 目录**(conf 文件、本地库、`server/` 下的 CA/服务器
证书及控制端自己的库;下次 `wgmgt server` 启动时全部重新生成,CA 指纹
随之改变,已注册的 agent 必须用新 token 重新注册),然后以空库继续向导。
选否则保留旧配置并提示后续步骤后退出。非交互环境默认保留,不再直接报错。

库文件为 node→client 改名**之前的旧 schema** 时,init 不再报 SQL 错误,
而是直接提供同一套全量重置确认(受管集合按 conf 目录里的 `*.conf`
判定,旧库打不开也能重置);非交互环境提示手动处理。

init 末尾直接进入**控制端 CA 步骤**,交互式依次询问 SAN 的 DNS 名与 IP
两项(非交互环境仅当给出 `--san-dns`/`--san-ip` 时执行):生成
`<conf-dir>/server/` 下的 CA 与服务器证书(DNS 默认取主机名,
`localhost`/`127.0.0.1`/`::1` 始终自动包含)。已有 CA 一律保留并打印指纹
(重新生成 CA 走全量重置);服务器证书的 SAN 已覆盖所填项则复用,否则
重签。这样 `wgmgt server` 启动时直接用现成证书,不再需要事后删
`server.pem` 换 `--api` 绑定重签——**起 server 时把 `--api` 绑定到所填
的某个名字/IP** 即可。

### `wgmgt delete [interface]`(设备在运行时需 root)

彻底删除一个受管接口:设备在运行则先 `down`(执行 PostDown、清策略
路由),再删库里的接口记录和全部 peer(级联),最后删生成的 conf 文件。
删除前显示摘要并要求确认;`--yes`/`-y` 跳过确认(脚本用)。非交互环境
不传 `--yes` 时默认中止。

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

### `wgmgt web [flags]`(需 root)

启动内嵌 Web UI:

```
$ sudo wgmgt web
WGMGT web UI: http://127.0.0.1:8080/t/913fc4cf45d2…/
```

- **鉴权**:每次启动生成随机 token,嵌在 URL 路径里——没有这个 URL
  的请求一律 404(同时挡住扫描器和浏览器 CSRF/DNS-rebinding)
- **刻意不内置 HTTPS**:Web UI 只做明文 HTTP。默认仅听 127.0.0.1
  (本机安全);需要远程访问时,`--port` 换端口 + **反向代理加 TLS**
  (推荐)或 SSH 隧道。`--global` 直接裸奔明文 HTTP,自担风险。
  典型反代配置(`wgmgt web --port 8080` 本机回环,caddy 一行):
  ```
  vpn.example.com {
      reverse_proxy 127.0.0.1:8080
  }
  ```
  nginx 等价写法:`proxy_pass http://127.0.0.1:8080;`(代理不要改写
  路径,token 在 URL 里)。`server` 的内置 CA 只服务 agent mTLS
  API(:8443),与 Web 控制台无关
- **功能**:仪表盘(接口卡片与状态)、接口详情(统计磁贴 + peer 表,
  5 秒自动刷新握手/流量)、表单加 peer(常用项 + 高级折叠区,对应
  双模式设计)、Up/Down 按钮、查看/复制客户端 conf
- 零前端构建链:HTML 模板 + 手写 CSS + 内嵌 htmx(go:embed),
  浅色/深色自适应

### `wgmgt server` / `wgmgt server token` / `wgmgt agent`(需 root,M3)

集中管理多客户端。协议:JSON + TLS + mTLS,agent 主动外连(NAT 后的
客户端唯一可行方向),**HTTP 长轮询**拉取配置——控制台一改,毫秒级
到达 agent(服务端 `--poll-hold` 默认 25s,0 关闭;须小于 agent 的
60s 响应超时);状态随每轮长轮询上报(节奏 ≈ hold)。agent 的
`--interval`(默认 30s)现在是失败重试的退避间隔。

```
# 1. 控制端(一次)
sudo wgmgt init                         # 接口向导末尾设置 CA 与服务器证书,
                                        # SAN 的 DNS 与 IP 分开询问(如公网 IP)
sudo wgmgt server --api <所填IP或域名>:8443 --web 9090 --web-global
                                        # --api 绑定到所填名字之一,SAN 才匹配;
                                        # 跳过 init 的 CA 步骤时,server 首次
                                        # 启动仍会自动生成(SAN 为主机名)

# 2. 添加客户端:生成一次性注册 token(每个客户端一次)
sudo wgmgt server token router1         # 或控制台「Add client」表单
#  → 打印一条完整的 join 命令(含 token 与 --ca-hash)

# 3. 目标客户端上,复制粘贴 join 命令即可
sudo wgmgt agent --server https://控制端:8443 \
    --token <一次性token> --ca-hash sha256:<控制端CA指纹>
#  → 自动生成密钥对、换取证书、落盘到 --conf-dir,随即进入正常轮询
```

注册(token enrollment)安全模型:

- **一次性 token**:48 字符,24 小时有效,单次使用即烧毁;库里只存
  哈希。烧毁在签证书**之前**(fail-closed:失败请求绝不可能签出第二张
  证书),但格式校验在烧毁之前(坏请求不浪费 token)
- **私钥不出客户端**:agent 在本地生成 ECDSA P-256 密钥对,注册请求只
  携带公钥;控制端为该公钥签发证书,MITM 拿不到私钥
- **CA pinning**:引导时 agent 尚无 CA,`--ca-hash` 把控制端根证书
  指纹钉死(kubeadm join 同款思路),防止首连被中间人劫持;服务端
  出示链尾部带根证书以供比对
- token 在命令行上短暂可见(`ps`),与 kubeadm 同款 tradeoff;
  join 命令页在控制台只显示一次
- 证书材料落盘 `--conf-dir`(ca.pem / agent.pem / agent.key,key 0600),
  agent 重启时检测到已有材料会**跳过注册**(token 已烧毁),直接复用

旧的 `wgmgt server enroll`(控制端本地签发证书 + 手工拷贝三个 PEM
文件)仍然可用,适合不方便传递 token 的场景。

常用 flag:

| 命令 | Flag | 默认 | 说明 |
|------|------|------|------|
| `server` | `--api` | `:8443` | agent API 监听地址(mTLS);**绑定到 init 所填 SAN 名之一**,agent 按该地址拨号才能通过证书校验 |
| | `--web` | `8080` | 控制台端口 |
| | `--web-global` | 关 | 控制台监听全网卡(默认仅 127.0.0.1;明文 HTTP 有警告) |
| | `--poll-hold` | `25s` | 长轮询挂起上限(0 = 立即应答;须 < agent 的 60s 响应超时) |
| | `--dir` | `/etc/wireguard/wgmgt/server` | 控制端状态目录(CA + 数据库) |
| `server token` | `--ttl` | `24h` | 注册 token 有效期 |
| `agent` | `--token` | — | 一次性注册 token(引导路径;须配合 `--ca-hash`) |
| | `--ca-hash` | — | 控制端 CA 指纹(`sha256:<hex>` 或裸 hex,join 命令里带) |
| | `--interval` | `30s` | 失败重试退避(正常节奏由服务端长轮询驱动) |
| | `--verify-timeout` | `180s` | 看门狗:超时未验证即回退(0 关闭) |
| | `--conf-dir` | `/etc/wireguard/wgmgt-agent` | 生成 conf 与注册材料的目录 |

#### 全隧道(0.0.0.0/0)与自锁保护

peer 的 AllowedIPs 含默认路由时,wgmgt 启用 wg-quick 同款策略路由:
fwmark 标记隧道自身流量、默认路由进独立路由表(51820)、
`suppress_prefixlength` 保留 main 表更精确路由——隧道端点与同网段
管理地址不会被劫持。

**仍可能锁死**(默认路由正好覆盖到控制端的路径、隧道又不通时)。
针对 agent 客户端(锁死后无人能远程救援)内置**验证式看门狗**:

- agent 每次应用新配置后,必须在 `--verify-timeout`(默认 **180s**,
  `0` 关闭)内再次联系上控制端——下一轮完成的长轮询即证明配置没把
  客户端锁死
- 超时未验证:自动**回退**(停掉全部受管接口、清理策略路由),
  并进入**隔离**:该配置版本不再自动重试(避免"回退→重锁"死循环;
  注意版本号可能因删除接口而**下降**,修复后的配置即使版本号更低
  也会被应用)
- 控制台客户端卡片显示 `⚠ QUARANTINED` 徽章;修复配置(版本 bump)
  后 agent 自动重新应用
- 控制端自身故障不会误伤:已验证过的配置不受后续失联影响,
  只有"刚应用的新配置"才进入验证窗口

单元测试 + 三命名空间 E2E(故意投毒 0/0 假 peer → 自锁 → 自动回退
→ 隔离徽章 → 修复重应用)均已验证。

控制台(`wgmgt server` 打印的 token URL):

- **客户端总览**:在线状态(上报新鲜度)、接口数、最近上报时间、
  隔离徽章;每张卡片自带 **Delete client** 按钮(带确认框,删除该
  客户端的接口/peer/token,名字可复用;已注册的 agent 下次轮询
  auth 失败,死人开关自动回滚)
- **添加客户端**:表单填名字 → 生成一次性 token,展示完整 join 命令
  (仅显示一次;刷新即 404,重铸即可)
- **客户端详情页**:接口卡片、**Quick add peer**(选接口 + 名字,一步加
  peer)、**Enrollment** 区(注册状态/未兑换 token 的有效期、一键重铸
  token——重铸会吊销该客户端旧的未兑换 token;对已注册客户端即重新注册,
  新证书自动取代旧证书)
- **客户端详情 / 建接口**:表单向导(名称/地址/端口/MTU),agent 长轮询
  被即时唤醒,变更毫秒级生效
- **接口详情**:与单机版一致,但握手/流量来自 agent 实时上报;
  Up/Down 变为 **Enable/Disable**(改期望态,agent 收敛)
- **peer 管理**:表单与单机一致(含公钥导入),支持跨客户端互配

安全模型与边界:

- agent 证书 CN 即客户端名;无证书者连 TLS 握手都过不了
- 控制端持有所有客户端的接口私钥(集中式配置管理的固有代价)
- agent 无本地状态(除证书与生成的 conf),重启即重新收敛
- 地址/端口/MTU/默认路由变化会重建设备(短暂中断);纯 peer 增删
  热更新不断线

## 验证过的端到端测试

开发中用 netns + veth 对在本机模拟了完整的客户端-服务器握手与数据面
(见 [DEV.md](DEV.md) 的回归测试一节)。M3 另验证了:单机双 agent
(一个在根命名空间、一个在独立 netns)经同一控制台建隧道、跨客户端
握手、远程 enable/disable 收敛。

## 后续版本预告(未实现)

- Docker 镜像、OpenWrt ipk、梅林插件、交叉编译矩阵(M4)
