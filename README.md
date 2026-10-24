# eero-mcp

[![CI](https://github.com/fulviofreitas/eero-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/fulviofreitas/eero-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A read-only [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for the eero
(Amazon) mesh Wi-Fi cloud API. It lets an MCP host such as Claude Code, Claude Desktop or Cursor
answer questions about your own network: the account, networks, eero nodes, connected devices,
household profiles, health and diagnostics, network configuration, data usage and security
insights. The host starts `eero-mcp` as a child process and talks to it over stdio; there is no
daemon and no network listener.

> **Unofficial project.** eero-mcp is not affiliated with or endorsed by eero or Amazon. It uses
> eero's undocumented, reverse-engineered cloud API through
> [`rusteero`](https://github.com/fulviofreitas/rusteero), and that API can change without notice.

## Features

- **Read-only.** 40 tools, all of them reads. There is no tool that changes a setting, reboots,
  blocks, pauses, runs a test or logs in or out. The agent can see the network; it cannot change it.
- **Broad coverage.** Account, networks, eero nodes, devices, profiles, health, network
  configuration, data usage and insights, with eero's own field names and values passed through.
- **stdio transport.** JSON-RPC on stdout, logs on stderr; works with any MCP host that can launch
  a local command.
- **Shares your existing login, read-only.** Reuses the session created by
  [`eeroctl`](https://github.com/fulviofreitas/eeroctl) or
  [`eero-api`](https://github.com/fulviofreitas/eero-api) (OS keyring or credential file), or takes
  a token from the environment. It never writes, migrates or deletes a credential.
- **Secret redaction.** Wi-Fi and guest passwords, keys and tokens are replaced with `[REDACTED]`
  in every result.
- **Agent-friendly results.** Structured output with an output schema on every tool, stable error
  codes, a compact device summary and validated time windows.

## Requirements

- Rust 1.96 or newer to build from source. The built binary needs no Rust installation.
- System CA certificates at runtime (the TLS stack verifies against the OS trust store; minimal
  containers need the `ca-certificates` package or equivalent).
- An existing eero login: a session created with `eeroctl` or `eero-api`, or a session token (see
  [Configuration](#configuration)).

## Install

eero-mcp is not published to crates.io: it depends on `rusteero` 3.x, which is currently available
only as a git tag. Build it from the repository.

```bash
# Default build: reads the shared OS keyring entry, then credential files
cargo install --git https://github.com/fulviofreitas/eero-mcp --locked

# Headless build: no keyring support (containers, servers without a Secret Service)
cargo install --git https://github.com/fulviofreitas/eero-mcp --locked --no-default-features
```

Or build from a clone:

```bash
git clone https://github.com/fulviofreitas/eero-mcp.git
cd eero-mcp
cargo build --release          # add --no-default-features for the headless build
./target/release/eero-mcp --version
```

The binary is named `eero-mcp`; `cargo install` places it in `~/.cargo/bin`. The only command-line
options are `--help` and `--version`; everything else is configured through environment
variables.

## Configuration

The server never logs in. It reads an existing session, in this order (the first hit wins):

| Order | Source | Builds | Notes |
|---|---|---|---|
| 1 | `RUSTEERO_SESSION_TOKEN` | all | A non-empty, printable-ASCII session token, used as given (not trimmed). A set but invalid value fails startup. |
| 2 | The OS keyring entry shared with `eeroctl` and `eero-api` (service `eero-api`, account `auth-tokens`) | default (`keyring` feature) | Read only. A missing entry or any keyring error (for example no Secret Service on headless Linux) is skipped silently. |
| 3 | A credential-record file | all | `EERO_MCP_SESSION_FILE` when set (set but empty, unreadable or unparsable fails startup; a record without a usable token is a miss, and eeroctl's default file is then not read); otherwise eeroctl's `cookies.json`, found in `EEROCTL_CONFIG_DIR`, else `%APPDATA%\eeroctl` on Windows, else `~/.config/eeroctl`. |
| 4 | Nothing found | all | The server still starts and lists its tools; every call returns `authentication_required` until a credential appears. |

All environment variables:

| Variable | Meaning | Default |
|---|---|---|
| `RUSTEERO_SESSION_TOKEN` | Session token, the first credential source. Changing it needs a restart, and while it is set it wins over keyring and file re-logins. | unset |
| `EERO_MCP_SESSION_FILE` | Path of a credential-record file (the record format that eero-api 8.x and eeroctl write). When set it replaces eeroctl's default file; set but empty fails startup. | unset |
| `EEROCTL_CONFIG_DIR` | eeroctl's configuration directory; its `cookies.json` is the default credential file. | unset |
| `EERO_MCP_API_BASE_URL` | API base URL override, for testing against a local mock only. Accepted for `https`, or `http` on a loopback host; any other value fails startup. | the production eero cloud API |
| `RUST_LOG` | Log filter. Logs go to stderr. | `warn` |

**Keyring and headless builds.** The default build includes the `keyring` feature (Secret Service
on Linux, Keychain on macOS, Credential Manager on Windows). The headless build
(`--no-default-features`) has no keyring code at all and resolves credentials only from the
environment token or a credential file. The keyring crate picks its platform store once per
process: if no Secret Service was reachable when the server started, restart the server after it
becomes available (a credential file is picked up without a restart).

**Re-login without a restart.** After an authentication failure the server re-reads the sources
once and, if they now yield a different token, retries the call once. Logging in again with
`eeroctl` therefore needs no restart, unless `RUSTEERO_SESSION_TOKEN` is set.

**Logging.** Logs go to stderr only (stdout carries JSON-RPC). For debugging use
`RUST_LOG=eero_mcp=debug,rusteero=debug`. Avoid a bare `RUST_LOG=debug` or `trace`: it also enables
the MCP SDK, which logs every tool call's arguments and results. Debug logs contain request paths
with network, eero and device ids, so keep them on your machine.

### Getting a session

Log in with [`eeroctl`](https://github.com/fulviofreitas/eeroctl); eero-mcp then finds the session
in the shared keyring entry or in eeroctl's `cookies.json` without any further configuration:

```bash
pip install eeroctl            # or: brew install fulviofreitas/eeroctl/eeroctl
eero auth login                # one-time code by email or SMS
```

`eero-api` users can rely on the same keyring entry, or point `EERO_MCP_SESSION_FILE` at their
credential file.

**Accounts that sign in with Amazon.** The email or SMS one-time-code login that `eeroctl` and
`eero-api` use does not work for Amazon-login accounts. Workaround: create a standard eero account
(email or phone number), invite it as an admin of your network from the eero app, and log in with
that account. An admin has full access.

## Registering in MCP clients

Credentials are read from the keyring or a credential file by default, so a configuration entry
usually needs no secret at all. If the binary is not on the host's `PATH` (GUI hosts often do not
inherit your shell `PATH`), use its absolute path, for example the full path of
`~/.cargo/bin/eero-mcp`.

### Claude Code

```bash
# Credentials come from the shared keyring entry or eeroctl's cookies.json
claude mcp add eero -- eero-mcp

# Pin an explicit credential file or token with -e (the -- ends the option list)
claude mcp add eero -e EERO_MCP_SESSION_FILE=/path/to/cookies.json -- eero-mcp
claude mcp add --scope user eero -e RUSTEERO_SESSION_TOKEN="$EERO_TOKEN" -- eero-mcp

claude mcp list
```

`--scope` is `local` (the default), `user` or `project`. A token passed with `-e` is stored in
plain text in the Claude Code configuration; prefer the keyring or a credential file. If you do pass
a token, put it in a shell variable (for example `read -rs EERO_TOKEN`) rather than typing it into
the command, so it stays out of your shell history.

### Claude Desktop

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`; Windows:
`%APPDATA%\Claude\`) and restart Claude Desktop:

```json
{
  "mcpServers": {
    "eero": {
      "command": "/absolute/path/to/eero-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

### Cursor

Add the same entry to `mcp.json` in the `.cursor` folder of your home directory (all projects) or
of a project directory (that project only):

```json
{
  "mcpServers": {
    "eero": {
      "command": "/absolute/path/to/eero-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

### Any other MCP host

Register a stdio server whose command is the `eero-mcp` binary, with no arguments. Optional
environment variables go in the host's `env` map, for example
`"env": { "EERO_MCP_SESSION_FILE": "/path/to/cookies.json" }`. The server speaks MCP over
stdin/stdout and writes logs to stderr; hosts usually capture stderr in their own MCP log files.

## Tools

Every tool is annotated read-only (`readOnlyHint` true, `destructiveHint` false,
`idempotentHint` true, `openWorldHint` true), has a title, rejects unknown inputs, and publishes an
input and an output schema. `network_id` is optional on every network-scoped tool (see
[Behaviour notes](#behaviour-notes)); the tables list only the other key inputs. **Plus** marks
data that needs an eero Plus (or eero Secure) subscription; without it the call returns
`premium_required`.

### Account and networks

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `get_account` | Account owner, subscription status, network references | `refresh` | |
| `list_networks` | Network entries (ids and names) as one list | `refresh` | |
| `get_network` | The richest single view of a network: health, status, DNS, security and Wi-Fi settings (Wi-Fi password redacted) | `refresh` | |
| `get_guest_network` | Guest Wi-Fi state and settings (password redacted) | | |
| `list_network_members` | The owner and admins | | |
| `get_network_permissions` | What the signed-in account may do on the network | | |
| `get_premium_features` | Active eero Plus and eero Secure features | | |

### eero nodes

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `list_eeros` | Mesh nodes: status, model, firmware, gateway role | `refresh` | |
| `get_eero` | One node in detail, including LED state (never cached) | `eero_id` (required) | |
| `list_eero_connections` | Clients attached to one node | `eero_id` (required) | |

### Devices

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `list_devices` | Devices on the network: a compact summary by default, or the full redacted list | `detail` (`summary` or `full`), `refresh` | |
| `get_device` | One device in detail | `device_id` (required), `refresh` | |
| `list_blocked_devices` | Devices blocked from the network | | |
| `get_transfer_stats` | Transfer statistics for the network or one device (some accounts get a 403) | `device_id` | |

### Profiles

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `list_profiles` | Household profiles and their paused state | `refresh` | |
| `get_profile` | One profile and its devices | `profile_id` (required), `refresh` | |
| `list_profile_schedules` | Pause schedules and bedtime for a profile | `profile_id` (required) | |
| `get_profile_blocked_apps` | Apps blocked for a profile | `profile_id` (required) | Yes |

### Health and activity

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `list_speed_tests` | ISP speed-test history (never starts a test) | `limit` (1 to 100), `start`, `end` | |
| `get_diagnostics` | The latest diagnostics results (never starts a run) | | |
| `get_firmware_updates` | Firmware update status and schedule | | |
| `get_channel_utilization` | Wi-Fi channel congestion over time, with the effective window | `start`, `end`, `eero_id`, `band`, `granularity`, `busy_threshold` | |
| `get_network_scan` | Neighbouring networks and interference | | |
| `list_activity_events` | One page of recent network events | `page_size` (1 to 100), `before` | |
| `list_notifications` | Alert history shown in the eero app (never marks anything read) | `before` | |

### Network configuration

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `list_port_forwards` | Port-forwarding rules (which ports are exposed) | | |
| `list_dhcp_reservations` | Fixed IP assignments | | |
| `get_subnets` | Subnet segmentation | | |
| `get_wpa3_settings` | WPA3 state per radio band | | |
| `get_fast_transition` | The 802.11r fast-roaming setting | | |
| `get_content_filter` | Network-wide allow and block lists | | Yes |
| `get_backup_internet` | Backup internet configuration | | Yes |

### Usage and insights

All tools in this group are time-windowed (default: the last 7 days, `cadence` `daily`) and echo
the effective window.

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `get_data_usage` | Network data usage over the window | `start`, `end`, `cadence`, `timezone` | |
| `get_devices_data_usage` | Per-device usage ranking | `start`, `end`, `cadence`, `timezone`, `profile_id` (filter) | |
| `get_device_data_usage` | One device's usage | `device_mac` (required), `start`, `end`, `cadence`, `timezone` | |
| `get_eeros_data_usage` | Usage per mesh node | `start`, `end`, `cadence`, `timezone` | |
| `get_profile_data_usage` | One profile's usage | `profile_id` (required), `start`, `end`, `cadence`, `timezone` | |
| `get_insights` | Security and ad-block insights (threats, blocks, inspections) | `start`, `end`, `cadence`, `insight_type` | Likely |
| `get_devices_insights` | The same insights ranked per device | `start`, `end`, `cadence`, `insight_type` | Likely |
| `get_device_insights` | Insights for one device | `device_id` (required), `start`, `end`, `cadence`, `insight_type` | Likely |

## Behaviour notes

**Choosing a network.** Every tool except `get_account` and `list_networks` (which take no
`network_id`) accepts an optional `network_id`. When omitted, the server uses the account's only
network. With several networks it returns `invalid_argument` (field `network_id`) listing each
network's id and name so the agent can choose; with none it returns `not_found`. It never silently
picks the first network. Every network-scoped result carries the `network_id` that was actually
queried.

**Id forms.** Ids (`network_id`, `eero_id`, `device_id`, `profile_id`) accept a bare id, an API path
naming one resource (for example `/2.2/networks/network-0001`), or an absolute URL on the eero API
origin; a JSON number is accepted too. `device_id` also accepts a MAC address in any common
spelling, and `device_mac` takes the MAC as `list_devices` shows it. Ids are validated and reduced
to the bare id before any request. A device or profile path must belong to the addressed network.
Empty ids are rejected rather than passed on.

**Results.** A successful call returns `structuredContent` and the same object as one compact JSON
text block (for hosts that predate structured content), for example from `list_devices` (abridged):

```json
{
  "data": [ { "id": "device-0001", "mac": "aa:bb:cc:00:00:01", "ip": "192.0.2.10", "connected": true } ],
  "network_id": "network-0001",
  "detail": "summary",
  "count": 1
}
```

| Member | Present on | Content |
|---|---|---|
| `data` | every tool | eero's data as eero returned it, secrets redacted (see below) |
| `network_id` | tools that take `network_id` | the network actually queried, as a bare id |
| `server_time` | when eero sends it | the server time from eero's response metadata |
| `window` | `get_channel_utilization` and the usage and insight tools | the effective time window |
| `detail`, `count` | `list_devices` | the mode used and the number of devices |

Tools return eero's `data` as-is, so field names match eero's API and nothing drifts when eero
changes a payload. Only `list_networks` unwraps its list container, and only `list_devices` trims
anything (in its default mode).

**`list_devices`: summary versus full.** Real networks have 100 or more devices of about 2 KB
each, so `detail: "summary"` (the default) keeps only the useful fields, when present: `id`, `url`,
`mac`, `nickname`, `hostname`, `display_name`, `manufacturer`, `device_type`, `model_name`, `ip`,
`ips`, `connected`, `wireless`, `connection_type`, `interface` (frequency), `source` (the eero it
is attached to), `profile`, `blocked`/`blacklisted`, `paused`, `prioritized`, `is_guest`,
`last_active` and `first_active`. Use `detail: "full"` for the complete redacted list, or
`get_device` for one device.

**Refresh and the 60 s cache.** The server reuses rusteero's client cache, which holds eight reads
for 60 seconds: `get_account`, `list_networks`, `get_network`, `list_eeros`, `list_devices`,
`get_device`, `list_profiles` and `get_profile`. Exactly those tools take `refresh: true`, which
skips the cache for that call (the fresh response is still stored). Every other tool is always
live; `get_eero` is never cached and has no `refresh`. Choosing a default network uses the cached
network list.

**Time windows.** These apply to `get_channel_utilization` and the usage and insight tools.
`start` and `end` are RFC 3339 timestamps such as `2026-10-16T00:00:00Z`; `start` must be before
`end`. With both omitted the window is the last 7 days ending now (the last 24 hours for
`get_channel_utilization`); with one omitted the other is derived with the same span. The result
echoes the effective `window`.

| Input | Values | Default |
|---|---|---|
| `cadence` | `daily`, `hourly` | `daily` |
| `timezone` | an IANA zone name (`get_data_usage` through `get_profile_data_usage`), validated by eero | not sent |
| `insight_type` | `inspected`, `blocked`, `malware`, `phishing`, `botnet`, `filtered`, `adult`, `illegal`, `violent`, `adblock`, `datausage` | `blocked` |
| `band` | `band_2_4GHz`, `band_5GHz_low`, `band_5GHz_high`, `band_5GHz_full`, `band_6GHz` | not sent |

`list_speed_tests` takes optional `start` and `end` that are passed through unchanged, with no
default window. `limit` and `page_size` accept 1 to 100; `before` is an RFC 3339 cursor timestamp;
`granularity` and `busy_threshold` are positive integers.

**Redaction.** Every result is redacted recursively: a value is replaced by `"[REDACTED]"` when its
key, compared case-insensitively, exactly equals one of: `password`, `passphrase`, `psk`,
`pre_shared_key`, `wpa_key`, `network_key`, `pskc`, `master_key`, `private_key`, `secret`,
`client_secret`, `api_key`, `token`, `user_token`, `access_token`, `refresh_token`, `session_id`,
`session_token`, `auth_token`, `temporary_token`, `activation_token`, `guardian_secret`,
`authentication_key`, `commissioning_credential`, `pppoe_credentials`. Null and empty values are
kept, so "no password set" stays visible. Matching is exact on purpose: MAC addresses, SSIDs,
serial numbers and email addresses are **not** redacted, because they are the data you are asking
about.

**Errors.** A failed call returns `isError: true` and one text block holding
`{"error": {...}}` with a stable `code`, a fixed `message` (never a token, URL or raw response) and,
when they apply, `field`, `retry_after_seconds`, `upstream_status` and `upstream_code`:

```json
{ "error": { "code": "rate_limited", "message": "...", "retry_after_seconds": 30, "upstream_status": 429 } }
```

| Code | Meaning | What to do |
|---|---|---|
| `authentication_required` | No session, or it expired or was revoked | Log in again with `eeroctl` (picked up automatically unless `RUSTEERO_SESSION_TOKEN` is set), or restart with a fresh token |
| `premium_required` | The data needs eero Plus (or eero Secure) | Nothing to retry; the network has no such subscription |
| `feature_unavailable` | The eero is offline, or its hardware or firmware lacks the feature | Check the node, or accept that the feature is unsupported |
| `rate_limited` | eero is throttling requests | Wait `retry_after_seconds`; the server never retries rate limits |
| `not_found` | Resource missing, no networks on the account, or not supported on this network or firmware | Check the id; some endpoints answer 404 on some firmware |
| `access_denied` | The signed-in account lacks permission | Not a session problem; use an account with the right role |
| `client_blocked` | eero rejected this client version | Update eero-mcp |
| `invalid_argument` | A bad id, time window or ambiguous network; `field` names the parameter | Fix the named field, or pick one of the listed network ids |
| `timeout` | The eero cloud API did not answer in time | Try again |
| `network_error` | Connection, DNS or TLS failure reaching the eero cloud | Check connectivity and CA certificates |
| `upstream_error` | eero returned an error status (including a 403 without an access-denied code) or an unexpected response | Inspect `upstream_status`; the API may have changed |
| `credential_error`, `internal_error` | Not expected in normal operation | Report an issue |

Type errors (an unknown input field, a wrong type, a value outside an enumeration) are reported by
the MCP SDK as plain text starting with `failed to deserialize parameters`, not in the JSON shape
above.

## Security and privacy

- **Read-only by construction.** The server calls only the 40 catalogued rusteero read methods. A
  test scans the source and fails the build if any write, action, login or logout method, or a
  raw API request, appears in it.
- **Credentials are only read.** The rusteero client is built with an explicit session and no
  credential store, so nothing is written, migrated, promoted or deleted. The shared keyring entry
  and `cookies.json` are parsed from their raw contents, never through a store that could rewrite
  them. A failed session refresh can clear only the in-memory session.
- **The token stays secret.** It is held as a secret in memory, and never logged, returned in a
  result or placed in error text. eero-mcp's own logs never carry credentials, credential file
  paths or response bodies. Redirects are always refused, and credentials are sent only to the
  configured eero API origin.
- **One automatic non-GET request.** When eero answers a request with a 401 carrying the
  `error.session.refresh` code, rusteero sends a single `POST /2.2/login/refresh` (authenticated by
  the current token) and replays the original request once. This is session maintenance, not a
  change to your network, and it is the only non-GET request the server can cause. The token does
  not rotate.
- **Your data goes only to your MCP host.** There is no network listener and no telemetry. The
  server's only outbound traffic is to the eero cloud API. Results still contain your own network
  data (device names, MAC addresses, IP addresses, the account email): that is the purpose of the
  server, and it is handed to whichever MCP host and model you connect.
- **Keep secrets out of configuration.** A token placed in a host's `env` map is stored there in
  plain text; prefer the keyring or a credential file.

## Testing with the MCP Inspector

The [MCP Inspector](https://github.com/modelcontextprotocol/inspector) CLI can list and call the
tools without a full MCP host. Put `--cli` first, pass the server's environment with `-e` (the
Inspector does not forward your shell environment to the server), and pass tool arguments with
`--tool-args-json`:

```bash
# List the tools (add --strict to report schema portability problems)
npx -y @modelcontextprotocol/inspector@2.12.0 --cli -q --format json \
  -e RUSTEERO_SESSION_TOKEN=test-token -e EERO_MCP_API_BASE_URL=http://127.0.0.1:8080 \
  target/release/eero-mcp --method tools/list

# Call one tool against a local mock API listening on 127.0.0.1:8080
npx -y @modelcontextprotocol/inspector@2.12.0 --cli -q --format json \
  -e RUSTEERO_SESSION_TOKEN=test-token -e EERO_MCP_API_BASE_URL=http://127.0.0.1:8080 \
  target/release/eero-mcp --method tools/call --tool-name get_network \
  --tool-args-json '{"network_id":"network-0001"}'
```

Exit codes: 0 success, 5 an `isError` result or an unknown tool, 1 a JSON-RPC error, 6 a `--strict`
error. Pass ids with `--tool-args-json`: the `--tool-arg key=value` form turns numeric-looking ids
into numbers. Against a real session the output contains your real network data; do not paste or
commit it.

## Development

```bash
cargo fetch --locked                      # all platforms' sources; the read-only guard test runs offline
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked --all-features        # offline: mocked HTTP and an in-process MCP client
cargo test --locked --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
cargo deny --all-features check           # licences, advisories, bans, sources
```

The offline test suite runs every tool end to end against a mocked eero API, and includes schema
and read-only guard tests. All fixtures are synthetic, and a tripwire expects zero non-GET
requests.

The live tests (`tests/live.rs`) read the real eero cloud through a hand-written read-only
allowlist. They are `#[ignore]`d, additionally gated on `EERO_MCP_LIVE=1`, print only result codes
and counts, and are meant to be run by a person, never in CI:

```bash
EERO_MCP_LIVE=1 cargo test --all-features --test live -- --ignored --nocapture
```

CI (`CI Pipeline`) runs commit lint, rustfmt and clippy, the tests on Linux, macOS and Windows with
and without the `keyring` feature, rustdoc, `cargo deny`, and an MSRV check against the
`rust-version` in `Cargo.toml`. All cargo steps use `--locked`. Commits follow
[Conventional Commits](https://www.conventionalcommits.org/) with a header of at most 100
characters. eero-mcp follows semantic versioning; the public contract is the MCP surface: tool
names, input names and types, output members, error codes and configuration variables.

## Limitations

- **eero Plus.** Content filters, blocked apps, backup internet and, most likely, the insights need
  an eero Plus or eero Secure subscription; the server reports `premium_required` without one.
- **Rate limits.** eero-api documents roughly 100 requests per minute. The server caps concurrent
  upstream calls at 4, reuses the 60 s cache and never retries a rate limit (`rate_limited` carries
  `retry_after_seconds`).
- **Amazon-login accounts** cannot use the one-time-code login; see
  [Getting a session](#getting-a-session) for the workaround.
- **403 and 404 on some accounts or firmware.** `get_transfer_stats` returns a 403 on some
  accounts, and some endpoints answer 404 on some firmware or networks.
- **Undocumented API.** The API is reverse-engineered and can change; data is returned as-is, so
  new or renamed fields pass through, and unexpected responses become `upstream_error`.
- **Cached reads can be up to 60 seconds old.** Use `refresh: true` where a tool offers it.
- **No login flow, one account per process.** The server cannot log in (the one-time-code flow
  sends a message and cannot prompt over stdio). Run a second server entry for a second account and
  give it its own `RUSTEERO_SESSION_TOKEN`, which wins over every other source. With the default
  chain both entries read the same keyring entry or `cookies.json` and so get the same account, and
  in the default build a populated keyring entry is read before `EERO_MCP_SESSION_FILE`, so a
  separate credential file alone only works in the headless build (`--no-default-features`).
- **`get_network_scan`** is a read, but eero does not document whether reading it refreshes the
  radio scan server-side.

## Acknowledgments

eero-mcp is built on [`rusteero`](https://github.com/fulviofreitas/rusteero), a Rust port of
[`eero-api`](https://github.com/fulviofreitas/eero-api), which is itself a modern revamp of
[`eero-client`](https://github.com/343max/eero-client) by [@343max](https://github.com/343max).
The shared login comes from [`eeroctl`](https://github.com/fulviofreitas/eeroctl). The server uses
the official Rust MCP SDK,
[`rmcp`](https://github.com/modelcontextprotocol/rust-sdk). See [NOTICE](NOTICE) for the full
attribution.

## License

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
