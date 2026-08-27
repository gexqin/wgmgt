# WGMGT

An open-source helper tool for deploying, managing, and visualizing
[kernel WireGuard](https://www.wireguard.com/) — from standard Linux servers
and Docker to ASUS Merlin and OpenWrt routers.

> If the running kernel does not include WireGuard support, WGMGT reports the
> system as incompatible. There is no userspace (wireguard-go) fallback.

## Status

M0 (skeleton + kernel compatibility check). Everything else is planned.

## Build

```sh
go build ./cmd/wgmgt
```

## Usage

```sh
wgmgt version   # print version
wgmgt doctor    # check kernel WireGuard compatibility
```
