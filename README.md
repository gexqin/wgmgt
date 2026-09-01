# WGMGT

[![Status: M3](https://img.shields.io/badge/status-M3-blue)](docs/PLAN.md)
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

Static, version-injected builds (what gets shipped) — see
[DEV.md](docs/DEV.md):

```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w \
  -X github.com/gexqin/wgmgt/internal/cli.version=$(git describe --tags --always) \
  -X github.com/gexqin/wgmgt/internal/cli.commit=$(git rev-parse --short HEAD)" \
  -o wgmgt ./cmd/wgmgt
```

## Quick start

```sh
sudo wgmgt init                     # wizard: create an interface
sudo wgmgt peer add --name laptop   # generates keys, prints client conf
sudo wgmgt up                       # native netlink bring-up
sudo wgmgt status                   # handshakes and traffic
sudo wgmgt delete                   # tear down + remove an interface

sudo wgmgt web                        # embedded web UI (token-protected)
sudo wgmgt server                     # controller: mTLS agent API + web console
sudo wgmgt server --web 9090 --web-global   # custom port, listen on all interfaces

# Adding a node — one-time enrollment token (or use the console's
# "Add node" form, which prints the same join command once):
sudo wgmgt server token router1
# On the node: a single command enrolls and starts the agent. The node
# generates its own keypair (the private key never travels) and pins the
# controller CA via the printed fingerprint.
sudo wgmgt agent --server https://ctrl:8443 \
    --token <one-time-token> --ca-hash sha256:<controller-CA-fingerprint>

# Legacy flow (issue certs on the controller, copy the files manually)
# is still available: wgmgt server enroll router1

wgmgt doctor                        # check kernel WireGuard compatibility
```

## Status

M3 — single-host CLI loop, embedded web UI, and controller/agent
multi-node management complete. Nodes join via one-time enrollment tokens
(agent-generated keys, CA pinning on first contact); agents connect out
over mTLS and long-poll for their configuration (console changes reach
them in milliseconds; a store-level change hook wakes held polls), apply
it via netlink, and report live status with each poll cycle; the
controller web console manages nodes, interfaces, peers, and enrollment
tokens across the fleet. A dead-man switch rolls agents back out of
configurations that lock the node away from the controller. Verified
end-to-end with two agents in separate network namespaces building a
tunnel entirely through the console. See the
[roadmap](docs/PLAN.md) for what's next (router packages, releases).

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — source-available for any
**noncommercial** purpose (personal, research, education, charities,
government). Commercial use is not permitted. Note this makes the project
source-available rather than OSI "open source" by definition.
