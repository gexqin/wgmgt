# WGMGT 使用说明

> 当前版本处于 **M0**(骨架 + 内核兼容检测),命令集很小。
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

WGMGT **只使用内核 WireGuard**,不内置任何用户态实现。运行前请确认:

- 内核版本 ≥ 5.6(WireGuard 并入主线),或
- 系统装有 out-of-tree 的 wireguard 内核模块(dkms 等)

不确定的话,先跑 `wgmgt doctor`。

## 命令

### `wgmgt version`

打印版本、commit、平台:

```
$ wgmgt version
wgmgt dev (none) linux/amd64
```

正式发布版本通过 `-ldflags` 注入版本号。

### `wgmgt doctor`

检测当前系统是否具备内核 WireGuard 支持。检测链:

1. `/proc/modules` — 模块是否已加载
2. `modules.builtin` — 是否内建进内核
3. `modules.dep` — 模块存在但未加载
4. netlink 探测 — 请求 wireguard generic-netlink family(终极判定;
   会顺带触发模块自动加载)

示例输出:

```
$ wgmgt doctor
Kernel: 6.6.87.2-microsoft-standard-WSL2
  - modules.dep: wireguard module present but not loaded
  - netlink: wireguard family responding
Verdict: COMPATIBLE — kernel WireGuard is usable
```

判定与退出码:

| Verdict | 含义 | 退出码 |
|---------|------|--------|
| `COMPATIBLE — kernel WireGuard is usable` | 已加载或内建,可立即使用 | 0 |
| `COMPATIBLE — module present but not loaded` | 模块在但没加载,需 `sudo modprobe wireguard` | 0 |
| `INCOMPATIBLE` | 系统无内核 WireGuard,WGMGT 无法工作 | 1 |

退出码可用于脚本判断。

## 后续版本预告(未实现)

- `wgmgt init` — 向导式创建 WG 接口与 peer(M1)
- `wgmgt up / down` — 接口管理(M1)
- `wgmgt peer add/list/rm` — peer 全生命周期(M1)
- `wgmgt status` — 状态与流量统计(M1)
- `wgmgt web` — 内嵌 Web UI(M2)
- `wgmgt server / wgmgt agent` — 多节点集中管理(M3)
