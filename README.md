# brew-server

Experimental Rust Brew core for linking two or more MidnightBlue Basestation or Flowstation TETRA base stations.

Reference spec from https://wiki.tetrapack.online/tetra/specifications/brew/

- **What's new:** see [CHANGELOG.md](CHANGELOG.md)
- **Configuration and feature docs:** see the [wiki](https://github.com/ysamouhos/brew-server/wiki)

## Run directly

Requires a Rust toolchain and a C compiler (the vendored ACELP codec in
`third_party/tetra-codec/` is compiled by `build.rs`).

```bash
cargo run --release -- sample/brew-server.toml   # the example; copy and edit it for your own
```

## Run via Docker

```bash
docker compose up --build
```

## Health check

```bash
curl http://127.0.0.1:9000/healthz
```

With `[ha]` enabled, the Brew `/healthz` answers only on the Active node; the
dashboard's `/healthz` (port 9003) answers on both, with the node's role.

## High availability

Two brew-servers can run as an active/standby pair sharing a virtual IP on
one LAN. See [docs/High-Availability.md](docs/High-Availability.md).
