# WGMGT

[![Status: M0](https://img.shields.io/badge/status-M0-blue)](docs/PLAN.md)

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
wgmgt version   # print version
wgmgt doctor    # check kernel WireGuard compatibility
```

## Status

M0 (skeleton + kernel compatibility check). See the
[roadmap](docs/PLAN.md) for what's next.
