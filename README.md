# WGMGT

[![Status: M2](https://img.shields.io/badge/status-M2-blue)](docs/PLAN.md)
[![License: PolyForm NC](https://img.shields.io/badge/license-PolyForm--NC--1.0.0-orange)](LICENSE)

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

sudo wgmgt web                        # embedded web UI (token-protected)

wgmgt doctor                        # check kernel WireGuard compatibility
```

## Status

M2 — single-host CLI loop and embedded web UI complete. The web UI
(HTMX, zero frontend build chain) shows interfaces, live handshakes and
traffic, and manages peers with wizard-style forms; it is protected by a
per-run random token embedded in the URL and listens on loopback by
default. See the [roadmap](docs/PLAN.md) for what's next (server+agent,
router packages).

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — source-available for any
**noncommercial** purpose (personal, research, education, charities,
government). Commercial use is not permitted. Note this makes the project
source-available rather than OSI "open source" by definition.
