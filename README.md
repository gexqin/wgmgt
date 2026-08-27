# WGMGT

[![Status: M1](https://img.shields.io/badge/status-M1-blue)](docs/PLAN.md)

An open-source helper tool for deploying, managing, and visualizing
[kernel WireGuard](https://www.wireguard.com/) — from standard Linux servers
and Docker to ASUS Merlin and OpenWrt routers.

> If the running kernel does not include WireGuard support, WGMGT reports the
> system as incompatible. There is no userspace (wireguard-go) fallback.

## Documentation (中文)

- [使用说明 Usage](docs/USAGE.md)
- [项目计划 Plan & roadmap](docs/PLAN.md)
- [开发文档 Development](docs/DEV.md)

## Build

```sh
go build -o wgmgt ./cmd/wgmgt
```

## Quick start

```sh
sudo wgmgt init                     # wizard: create an interface
sudo wgmgt peer add --name laptop   # generates keys, prints client conf
sudo wgmgt up                       # native netlink bring-up
sudo wgmgt status                   # handshakes and traffic

wgmgt doctor                        # check kernel WireGuard compatibility
```

## Status

M1 — single-host CLI loop complete (interface/peer lifecycle, SQLite
storage, wg-quick conf generation, native netlink up/down, live status).
End-to-end handshake verified. See the [roadmap](docs/PLAN.md) for what's
next (web UI, server+agent, router packages).
