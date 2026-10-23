# eero-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for the eero
mesh Wi-Fi cloud API. It lets an MCP host (Claude Code, Claude Desktop, Cursor and others) answer
questions about your own network: the account, networks, eero nodes, devices, profiles, health,
network configuration and data usage. It talks to the host over stdio.

> **Unofficial project.** This server uses a reverse-engineered API through
> [`rusteero`](https://github.com/fulviofreitas/rusteero) and is not affiliated with or endorsed by
> eero or Amazon.

**Status:** under development. The account tools are implemented first; the remaining tool groups
are added one by one.

## Read-only

The server only ever reads. It has no tool that changes a setting, reboots, blocks, pauses or runs
anything, and it never logs in or out. The source is scanned by a test that fails if any write
path, credential-store type or credential write appears in it. Secret values (Wi-Fi and guest
passwords, keys, tokens) are redacted from every result.

## Credentials

The server never logs in. It reads a session that you created with `eeroctl` or `eero-api`, in this
order (first hit wins):

1. `RUSTEERO_SESSION_TOKEN`;
2. the OS keyring entry shared with `eeroctl` and `eero-api` (builds with the default `keyring`
   feature; build with `--no-default-features` for a headless binary);
3. the credential file named by `EERO_MCP_SESSION_FILE`, otherwise eeroctl's `cookies.json`
   (`EEROCTL_CONFIG_DIR`, else `~/.config/eeroctl`).

Credentials are only read, never written, migrated or deleted. After an authentication failure the
sources are read again, so logging in again with `eeroctl` needs no restart.

## Logging

Logs go to stderr (stdout carries only JSON-RPC). The default filter is `warn`. For debugging use
`RUST_LOG=eero_mcp=debug,rusteero=debug`. Avoid a bare `RUST_LOG=debug` or `trace`: it also enables
the MCP SDK, which logs every tool call's arguments and results (network names, MAC addresses).
Debug logs contain request paths with network, eero and device ids, so keep them on your machine.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The live tests (`tests/live.rs`) read the real eero cloud, are ignored by default and run only
with `EERO_MCP_LIVE=1 cargo test --all-features --test live -- --ignored --nocapture`.

## License

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
