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
| 11 | 配置存储(2026-08-27 补) | **SQLite 为唯一真相**,`wg-quick` 兼容 conf 是生成产物(改配置 → 写 DB → 重生成 conf → 应用);SQLite 自 M1 单机模式即引入。私钥存 DB,库文件与产物 conf 均 0600;硬件密钥延后 |
| 12 | Web UI 选型(2026-08-27 补) | **HTMX + 纯静态模板**,零前端构建链,embed 体积最小(M2) |
| 13 | server↔agent 协议(2026-08-27 定) | **JSON + TLS + mTLS**;agent 主动外连(NAT 后路由器唯一可行方向),pull 模型轮询配置(默认 30s,响应头提示变更可加速);agent 证书即身份,可吊销。gRPC 因路由器体积/内存硬约束被否 |
| 14 | 许可证(2026-08-27 定) | **PolyForm Noncommercial 1.0.0**——允许非商业用途(个人/研究/教育/公益/政府),禁止商用。严格说是 source-available 而非 OSI 开源;后果:进不了 OpenWrt 官方源(M4 走侧载/自建源),梅林插件影响较小 |

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
| **M1 单机 CLI 闭环** | `init` 向导/高级模式、接口 up/down、peer 增删查(含 `--public-key` 导入)、配置持久化(SQLite + conf 生成)、`status` 含流量统计;netns+veth 端到端握手已验证 | ✅ 完成 |
| **M2 单机 Web UI** | go:embed 内嵌 HTMX UI、接口卡片/统计磁贴/peer 表(5s 刷新)、表单加 peer(向导+高级折叠)、Up/Down、客户端 conf 查看;token-in-URL 鉴权,默认仅监听 127.0.0.1 | ✅ 完成 |
| **M3 主控 + agent** | server 集中管理多节点、agent 上报、配置下发、跨节点 peer 规划(自动分配地址段) | 计划 |
| **M4 平台适配** | 交叉编译矩阵(amd64/arm64/armv7)、Docker 镜像、OpenWrt ipk、梅林插件包 | 计划 |
| **M5 发布打磨** | CI/CD、语义化版本、文档站、发布流程 | 计划 |

## 未定事项(推进到相应里程碑前必须定)

暂无——M1 开工前的全部决策已定(见决策表 #11–#13)。

## 明确不做(Non-Goals)

- mesh 网络 / 真打洞(受内核 WG 限制)
- userspace wireguard-go 兼容层
- 防火墙/nftables 全功能管理(只做 WG 所需的最小联动提示)
- Windows/macOS 原生支持
