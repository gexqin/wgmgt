# WGMGT 项目计划

> 规划定稿于 2026-08-27,随开发滚动更新。当前状态:**M0 已完成**。

## 一句话定位

一个开源的 WireGuard 辅助管理工具——部署、配置、可视化**内核** WireGuard,
从标准 Linux 服务器到梅林/OpenWrt 路由器全覆盖,CLI 与 Web 双入口。

## 已定决策(2026-08-27)

| # | 决策点 | 结论 |
|---|--------|------|
| 1 | 项目名 | WGMGT,命令/二进制名 `wgmgt`,仓库 `github.com/gexqin/wgmgt` |
| 2 | 语言/形态 | Go,单一静态二进制,go:embed 内嵌 Web UI |
| 3 | 内核策略 | **只用内核 WireGuard 模块**;检测不到则报"系统不兼容",无用户态(wireguard-go)回退 |
| 4 | 架构 | 中心化:主控(server)+ 轻量 agent;**单机场景两者都不需要** |
| 5 | 运行模式 | 三种:本地单机(默认)/ `wgmgt server`(主控)/ `wgmgt agent`(执行器) |
| 6 | NAT 穿透 | 仅配置辅助级(MTU/keepalive/端口冲突检测/DDNS 提示);内核 WG 决定了无法真打洞 |
| 7 | 目标平台 | Linux 服务器/VM、Docker、华硕梅林(插件形态)、OpenWrt x64/ARM(ipk 包) |
| 8 | 功能范围 | peer 全生命周期管理、多节点/多隧道、流量统计与监控、NAT 配置辅助 |
| 9 | 使用门槛 | 双模式 UI:默认向导式一键完成 + 高级模式全参数暴露 |
| 10 | WG 控制 | wgctrl(netlink)操作内核;doctor 检测用自写 genl 探测(见 DEV.md) |

### 硬约束的推论

- 不捆绑 wireguard-go → 无 TUN 性能/内存问题,适合路由器小内存环境;
- 解释型语言被排除(路由器无 Python/Node 运行时,musl libc)→ Go 交叉编译;
- "内核 only" 同时是产品边界:**不做** mesh 网络、不做 userspace 兼容层。

## 架构总览

```
                ┌─────────────────────────────────┐
                │         主控 wgmgt server        │
                │  集中配置库 + Web UI + API 聚合   │
                └──────────┬──────────────────────┘
                           │ (agent 注册/心跳/配置下发)
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
│ wgmgt agent  │   │ wgmgt agent  │   │ wgmgt agent  │
│ 服务器/Docker │   │   梅林路由器  │   │  OpenWrt 路由 │
│      │       │   │              │   │              │
│ 内核 WG(netlink 直控,所有节点一致)│
└──────────────┘   └──────────────┘   └──────────────┘

单机模式(无 server/agent):CLI → netlink → 本机内核 WG,本地 SQLite 存配置
```

## 里程碑

| 里程碑 | 内容 | 状态 |
|--------|------|------|
| **M0 骨架** | git/go.mod、cobra CLI、`version`、`doctor`(内核 WG 检测) | ✅ 完成(commit e26988a) |
| **M1 单机 CLI 闭环** | `init` 向导/高级模式、接口 up/down、peer 增删查、配置持久化(`/etc/wireguard/wgmgt/`)、`status` 含流量统计 | 下一步 |
| **M2 单机 Web UI** | go:embed 内嵌 UI、只读可视化(拓扑/流量)+ 操作向导 | 计划 |
| **M3 主控 + agent** | server 集中管理多节点、agent 上报、配置下发、跨节点 peer 规划(自动分配地址段) | 计划 |
| **M4 平台适配** | 交叉编译矩阵(amd64/arm64/armv7)、Docker 镜像、OpenWrt ipk、梅林插件包 | 计划 |
| **M5 发布打磨** | CI/CD、语义化版本、文档站、发布流程 | 计划 |

## 未定事项(推进到相应里程碑前必须定)

1. **配置存储格式**(M1):自定义 YAML vs 直接生成 wg-quick 兼容 conf;
   单机是否真的需要 SQLite,还是文件即真相、SQLite 延后到 M3。
2. **Web UI 技术选型**(M2):纯静态 + HTMX(零构建、嵌入小)vs SPA(React/Vue,
   体验好但构建链重)。倾向前者,路由器场景 embed 体积敏感。
3. **server↔agent 协议**(M3):gRPC vs 简单 JSON+TLS;agent 无公网场景的连接方向
   (agent 主动外连)。
4. **密钥管理**(M1):私钥文件权限策略、是否支持硬件密钥(延后决策)。

## 明确不做(Non-Goals)

- mesh 网络 / 真打洞(受内核 WG 限制)
- userspace wireguard-go 兼容层
- 防火墙/nftables 全功能管理(只做 WG 所需的最小联动提示)
- Windows/macOS 原生支持
