# eero-mcp

[![CI](https://github.com/fulviofreitas/eero-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/fulviofreitas/eero-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for the eero (Amazon) mesh
Wi-Fi cloud API. It lets an MCP host such as Claude Code, Claude Desktop or Cursor answer questions
about your own network: the account, networks, eero nodes, connected devices, household profiles,
health and diagnostics, network configuration, data usage and security insights. The network tools
are read-only. eero-mcp also signs you in by itself, from a terminal (`eero-mcp login`) or from the
chat (the `login` tool), so you do not need another tool to get a session. The host starts
`eero-mcp` as a child process and talks to it over stdio; there is no daemon and no network
listener.

> **Unofficial project.** eero-mcp is not affiliated with or endorsed by eero or Amazon. It uses
> eero's undocumented, reverse-engineered cloud API through
> [`rusteero`](https://github.com/fulviofreitas/rusteero), and that API can change without notice.

## Features

- **Read-only network tools.** 40 tools, all of them reads. There is no tool that changes a
  setting, reboots, blocks, pauses or runs a test. The agent can see the network; it cannot change
  it. The one other tool, `login`, signs you in (see [Logging in](#logging-in)).
- **Its own login.** `eero-mcp login`, `logout` and `status` in a terminal, and a `login` tool for
  hosts that can show forms. The session is kept in eero-mcp's own store (the OS keyring, with its
  own file as the fallback), never in anyone else's.
- **Broad coverage.** Account, networks, eero nodes, devices, profiles, health, network
  configuration, data usage and insights, with eero's own field names and values passed through.
- **stdio transport.** JSON-RPC on stdout, logs on stderr; works with any MCP host that can launch
  a local command.
- **Reads an existing login too.** Reuses the session created by
  [`eeroctl`](https://github.com/fulviofreitas/eeroctl) or
  [`eero-api`](https://github.com/fulviofreitas/eero-api) (OS keyring or credential file), or takes
  a token from the environment. Those credentials are only ever read: eero-mcp never writes,
  migrates or deletes a credential it does not own.
- **Secret redaction.** Wi-Fi and guest passwords, keys and tokens are replaced with `[REDACTED]`
  in every result.
- **Agent-friendly results.** Structured output with an output schema on every tool, stable error
  codes, a compact device summary and validated time windows.

## Requirements

- Rust 1.96 or newer to build from source. The built binary needs no Rust installation.
- System CA certificates at runtime (the TLS stack verifies against the OS trust store; minimal
  containers need the `ca-certificates` package or equivalent).
- An eero login: run `eero-mcp login` (see [Logging in](#logging-in)), or reuse a session created
  with `eeroctl` or `eero-api`, or provide a session token (see [Configuration](#configuration)).

## Install

eero-mcp is installed from its repository (it is not published to crates.io); its eero client,
`rusteero`, comes from crates.io.

```bash
# Default build: keeps its login in the OS keyring (own file as the fallback) and also reads
# the keyring entry shared with eeroctl
cargo install --git https://github.com/fulviofreitas/eero-mcp --locked

# Headless build: no keyring support (containers, servers without a Secret Service); the login
# is kept in eero-mcp's own file
cargo install --git https://github.com/fulviofreitas/eero-mcp --locked --no-default-features
```

Or build from a clone:

```bash
git clone https://github.com/fulviofreitas/eero-mcp.git
cd eero-mcp
cargo build --release          # add --no-default-features for the headless build
./target/release/eero-mcp --version
```

The binary is named `eero-mcp`; `cargo install` places it in `~/.cargo/bin`. With no argument it
serves MCP over stdio. The only options are `--help` and `--version`, and exactly one of the
subcommands `login`, `logout` and `status` (see [Logging in](#logging-in)); any other argument is a
usage error (exit status 2). Everything else is configured through environment variables.

## Configuration

### Logging in

eero-mcp signs in by itself; it does not need `eeroctl`. eero sends a one-time code by email or SMS
to the account you sign in with.

**In a terminal.** This works with every MCP host:

```bash
eero-mcp login     # asks for your email address or phone number, then for the code eero sends
eero-mcp status    # shows which credential the server would use, and whether eero accepts it
eero-mcp logout    # signs eero-mcp's own session out and deletes it
```

- `login` prompts on stderr and reads your answers from stdin, one line at a time (so it also works
  from a script). An empty line, or the word `new`, asks eero to send the code again (at most 3
  times). A wrong or expired code starts the login again with a new code (at most 3 attempts in
  total); any other refusal, such as a blocked account, ends it without sending more messages.
  On success it saves the session to eero-mcp's own store, tells you where (the system keyring, or
  the file's path) and exits 0; every failure prints one fixed line and exits 1. If the session
  cannot be saved, it signs the new session out again, so no session that nothing stores stays
  live. The email address, phone number and code are never logged, echoed back or put in an error.
- `status` prints which credential source the server would use (`environment token`, `explicit
  file`, `eero-mcp keyring`, `eero-mcp file`, `eero-api keyring`, `eeroctl file` or `none`) and
  checks it with one account read: `valid`, `rejected` (log in again) or `unreachable`. It exits 0
  only when the session is valid, and never prints the token, your identifier, account details,
  ids or file paths.
- `logout` reads eero-mcp's own store and signs each session found there out at eero (one request;
  eero's answer is not observable, so the report says a sign-out request was sent), then deletes the
  own keyring entry and the own file and reports what it removed. It skips the sign-out for a token
  that another source (the environment token, the explicit file, the shared keyring entry or
  eeroctl's file) also holds, because that would end that login too, and says so. It names every
  store it could not check, for example the keyring when `EERO_MCP_NO_KEYRING=1`. It never touches
  the shared credentials, `RUSTEERO_SESSION_TOKEN` or the `EERO_MCP_SESSION_FILE` file. It exits 0
  when everything it found is gone (also when nothing was stored) and 1 when a record could not be
  deleted.

A running server picks up a login made in a terminal without a restart (see below).

**In the chat.** Ask your assistant to log you in: it calls the `login` tool. The tool needs a host
that supports MCP *form elicitation*: the server asks the host to show you a small form, first for
your email address or phone number (skipped when you gave it in the conversation) and then for the
code eero sent. The code is never a tool argument, so it never passes through the model. When the
login works, the session is saved to eero-mcp's own store and installed in the running server at
once. If the host cannot show forms, the tool returns `login_requires_terminal` and sends nothing
to eero: run `eero-mcp login` in a terminal instead.

> **A deliberate deviation from the MCP specification.** The MCP elicitation specification
> (2025-11-25) says servers must not use form mode to ask for sensitive information such as
> credentials, and must use URL mode instead. eero-mcp asks for the one-time code in a form anyway,
> because URL mode needs a browser on the machine that runs eero-mcp, which fails for remote and
> containerized hosts. The consequence: **your MCP host receives the code in the form response and
> may keep it in its logs or transcript.** The code never passes through the model or tool
> arguments. Mitigations: the code is single use and short-lived and one verification consumes it
> immediately; eero-mcp never logs, echoes or returns it; the session token itself is never put in
> a form; the identifier form asks only for contact information. If you do not trust your host's
> transcripts with a one-time code, use `eero-mcp login` in a terminal: it keeps the code out of the
> host entirely.

**Host tool-call timeouts.** Fetching the code from your mailbox or phone can take longer than your
host lets a tool call run. While a form is open and the call carries a progress token, the server
sends progress notifications (fixed text, never your identifier or the code), which some hosts use
to extend their timeout. If the host cancels the call, the login stops at once: nothing is saved
or installed, nothing more is sent to eero, and the next `login` call can start. If it gives up
without cancelling, the login waits until the form is answered or times out after 10 minutes. In
either case call `login` again, or use `eero-mcp login`. One login can run at a time.

**Where the session is kept.** In eero-mcp's own store, never in the store that `eeroctl` and
`eero-api` share:

| Build | Where | Notes |
|---|---|---|
| Default (`keyring` feature), keyring enabled | The OS keyring entry with service `eero-mcp` and account `auth-tokens`; eero-mcp's own file `session.json` as the fallback when the keyring cannot keep it | Every save is read back to prove it was kept. |
| Headless, or `EERO_MCP_NO_KEYRING=1` | The own file `session.json` alone | |

The own file lives in `EERO_MCP_CONFIG_DIR` when set; else, on Windows, in `%APPDATA%\eero-mcp`;
else in `$XDG_CONFIG_HOME/eero-mcp` (an absolute value only); else in `~/.config/eero-mcp`. It holds
the same record that `eeroctl` and `eero-api` write, is created with mode `0600` in a directory the
save creates with mode `0700` (Unix; Windows relies on the profile's access control), and is
replaced atomically. A symbolic link at its path is replaced, never followed. A new login replaces
the old record and removes a leftover copy in the other backend; it does not sign the earlier
session out (run `eero-mcp logout` first for that).

`login` and `logout` refuse to run, before sending anything, when `EERO_MCP_SESSION_FILE` names
eero-mcp's own session file: a login would overwrite, and a logout delete, a credential you
configured explicitly. Unset the variable (the own store is read anyway).

**Accounts that sign in with Amazon** cannot use the one-time-code login, here or with `eeroctl`.
Workaround: create a standard eero account (email or phone number), invite it as an admin of your
network from the eero app, and log in with that account. An admin has full access.

### Credential sources

The server resolves one session at startup, in this order (the first usable token wins). After an
authentication failure it re-reads the same chain, so a login made in a terminal is found without a
restart:

| Order | Source | Builds | Notes |
|---|---|---|---|
| 1 | `RUSTEERO_SESSION_TOKEN` | all | A non-empty, printable-ASCII session token, used as given (not trimmed). A set but invalid value fails startup. |
| 2 | `EERO_MCP_SESSION_FILE` | all | An explicit credential-record file. Set but empty, unreadable or unparsable fails startup; a record without a usable token is a miss and the search continues. Never written or deleted. |
| 3 | eero-mcp's own store: its keyring entry (service `eero-mcp`), then its own `session.json` | the keyring entry in the default build, unless `EERO_MCP_NO_KEYRING=1`; the file in all | What `eero-mcp login` and the `login` tool save. Written only by login, deleted only by logout. |
| 4 | The OS keyring entry shared with `eeroctl` and `eero-api` (service `eero-api`, account `auth-tokens`) | default (`keyring` feature), unless `EERO_MCP_NO_KEYRING=1` | Read only. A missing entry or any keyring error (for example no Secret Service on headless Linux) is skipped silently. |
| 5 | eeroctl's `cookies.json`, found in `EEROCTL_CONFIG_DIR`, else `%APPDATA%\eeroctl` on Windows, else `~/.config/eeroctl` | all | Read only. |
| 6 | Nothing found | all | The server still starts and lists its tools; every call returns `authentication_required` until a credential appears. |

A source that holds a record without a token (what `eeroctl` leaves after a logout) is a miss, never
a hit. A usable `RUSTEERO_SESSION_TOKEN` or `EERO_MCP_SESSION_FILE` takes precedence over a fresh
login (the login result and `eero-mcp login` say so).

All environment variables:

| Variable | Meaning | Default |
|---|---|---|
| `RUSTEERO_SESSION_TOKEN` | Session token, the first credential source. Changing it needs a restart, and while it is set it wins over every other source, logins included. | unset |
| `EERO_MCP_SESSION_FILE` | Path of an explicit credential-record file (the record format that eero-api 8.x and eeroctl write), the second source. Set but empty fails startup. Must not name eero-mcp's own session file (login and logout refuse). Used literally: `~` is not expanded (MCP host `env` maps do not expand it either), so give an absolute path. | unset |
| `EERO_MCP_CONFIG_DIR` | eero-mcp's own configuration directory, holding `session.json`. Must be an absolute path; set but empty or relative fails startup and every subcommand. | the platform default above |
| `XDG_CONFIG_HOME` | Systems other than Windows: base of the own directory when `EERO_MCP_CONFIG_DIR` is unset. Used only when absolute. | unset |
| `EERO_MCP_NO_KEYRING` | Default build: `1` skips both keyring entries (no read, no write); login then saves to the own file. Any other value, the empty value included, fails startup. No effect in the headless build. | unset: the keyring is used |
| `EEROCTL_CONFIG_DIR` | eeroctl's configuration directory; its `cookies.json` is the default credential file. Used literally: `~` is not expanded, so give an absolute path. | unset |
| `HOME` | Non-Windows: when `EEROCTL_CONFIG_DIR` is unset, the default credential file is `~/.config/eeroctl/cookies.json` under it; when neither `EERO_MCP_CONFIG_DIR` nor an absolute `XDG_CONFIG_HOME` is set, the own directory is `~/.config/eero-mcp` (an empty value counts as unset). | set by the OS |
| `APPDATA` | Windows: when `EEROCTL_CONFIG_DIR` is unset, the default credential file is `%APPDATA%\eeroctl\cookies.json`; when `EERO_MCP_CONFIG_DIR` is unset, the own directory is `%APPDATA%\eero-mcp`. | set by Windows |
| `EERO_MCP_API_BASE_URL` | API base URL override, for testing against a local mock only. Accepted for `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`, with no user name, password, query or fragment; any other value fails startup. The subcommands and the login tool honour it too. | the production eero cloud API |
| `EERO_MCP_LIVE` | Tests only: `1` lets the ignored live tests run. | unset |
| `RUST_LOG` | Log filter. Logs go to stderr. | `warn` |

**Keyring and headless builds.** The default build includes the `keyring` feature (Secret Service
on Linux, Keychain on macOS, Credential Manager on Windows). The headless build
(`--no-default-features`) has no keyring code at all: it resolves credentials from the environment
token and credential files, and keeps its login in the own file. The keyring crate picks its
platform store once per process: if no Secret Service was reachable when the server started,
restart the server after it becomes available (a credential file is picked up without a restart).
That also applies when a terminal login saved to the keyring while the server's process could not
reach it; set `EERO_MCP_NO_KEYRING=1` for both to keep the session in the own file.

**Re-login without a restart.** After an authentication failure the server re-reads the sources
once and, if they now yield a different token, retries the call once. A login made with `eero-mcp
login` (or `eeroctl`) is therefore found on the next call of a server that has no usable session, and
at the next authentication failure of a server whose session still works; the `login` tool installs
its session at once. A usable `RUSTEERO_SESSION_TOKEN` or `EERO_MCP_SESSION_FILE` wins every
re-read.

**Logging.** Logs go to stderr only (stdout carries JSON-RPC, or the subcommands' results). For
debugging use `RUST_LOG=eero_mcp=debug,rusteero=debug`. Avoid a bare `RUST_LOG=debug` or `trace`: it
also enables the MCP SDK, which logs every tool call's arguments and results (and, for `login`,
the identifier argument at debug level and the form answers, identifier and one-time code, at
trace). Debug logs contain request paths with network, eero and device ids, so keep them on your
machine.

### Reusing a session from eeroctl

If you already use [`eeroctl`](https://github.com/fulviofreitas/eeroctl), eero-mcp finds its
session in the shared keyring entry or in eeroctl's `cookies.json` without any further
configuration:

```bash
pip install eeroctl            # or: brew install fulviofreitas/eeroctl/eeroctl
eero auth login                # one-time code by email or SMS
```

`eero-api` users can rely on the same keyring entry, or point `EERO_MCP_SESSION_FILE` at their
credential file. eero-mcp only ever reads these.

## Registering in MCP clients

Credentials come from eero-mcp's own store, the keyring or a credential file by default, so a
configuration entry usually needs no secret at all: run `eero-mcp login` once in a terminal, or ask
the assistant to log you in. If the binary is not on the host's `PATH` (GUI hosts often do not
inherit your shell `PATH`), use its absolute path, for example the full path of
`~/.cargo/bin/eero-mcp`.

### Claude Code

```bash
# Credentials come from eero-mcp's own store (run eero-mcp login), the shared keyring entry or
# eeroctl's cookies.json
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

41 tools. The 40 network tools are annotated read-only (`readOnlyHint` true, `destructiveHint`
false, `idempotentHint` true, `openWorldHint` true). `login` is not read-only (`readOnlyHint` false,
`destructiveHint` false, `idempotentHint` false, `openWorldHint` true), so a host can ask before
running it. Every tool has a title, rejects unknown inputs, and publishes an input and an output
schema. `network_id` is optional on every network-scoped tool (see
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

### Session

| Tool | Returns | Key inputs | Plus |
|---|---|---|---|
| `login` | **Not read-only** (it sends eero's login requests and saves a session). Signs you in with a one-time code that eero sends by email or SMS; the code is asked for through the client's own form. Returns `logged_in`, `store` (`keyring`, `file`, or `memory` when the session could not be saved and lasts only until the server stops) and `notes`. Never the token or the identifier. | `identifier` (optional email address or phone number; pass it only when you typed it in the conversation) | |

Errors specific to `login`: `login_requires_terminal`, `login_cancelled` and `login_failed` (see
below), plus `invalid_argument` (field `identifier`), `rate_limited`, `network_error` and `timeout`.
`identifier` accepts a JSON string only: a phone number sent as a number would lose its leading plus
sign or zeros and could start a login for someone else's number. The tool is never called against
the real API by the tests, and a real call makes eero send you a message.

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
| `detail`, `count` | `list_devices` | the mode used and the number of devices; if eero sends a shape with no recognisable device list, `data` is the raw (redacted) data, `detail` is `full` and `count` is absent |

Tools return eero's `data` as-is, so field names match eero's API and nothing drifts when eero
changes a payload. `list_networks` and `list_devices` unwrap their list containers, and only
`list_devices` trims entries (in its default mode).

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
`start` and `end` are RFC 3339 timestamps such as `2026-10-16T00:00:00Z` (strict RFC 3339: a `T`
separator, seconds, and `Z` or a `+HH:MM` offset; a space separator or `+0000` is rejected);
`start` must be before `end`. With both omitted the window is the last 7 days ending now (the last 24 hours for
`get_channel_utilization`); with one omitted the other is derived with the same span. The result
echoes the effective `window`.

| Input | Values | Default |
|---|---|---|
| `cadence` | `daily`, `hourly` | `daily` |
| `timezone` | an IANA zone name (`get_data_usage` through `get_profile_data_usage`), validated by eero | not sent |
| `insight_type` | `inspected`, `blocked`, `malware`, `phishing`, `botnet`, `filtered`, `adult`, `illegal`, `violent`, `adblock`, `datausage` | `blocked` |
| `band` | `band_2_4GHz`, `band_5GHz_low`, `band_5GHz_high`, `band_5GHz_full`, `band_6GHz` | not sent |

`list_speed_tests` takes optional `start` and `end` (RFC 3339; with both given `start` must be
before `end`) that are passed through unchanged, with no default window. `limit` and `page_size` accept 1 to 100; `before` is an RFC 3339 cursor timestamp;
`granularity` and `busy_threshold` are integers from 1 to 4294967295.

**Redaction.** Every result is redacted recursively: a value is replaced by `"[REDACTED]"` when its
key, compared case-insensitively, exactly equals one of: `password`, `passphrase`, `psk`,
`pre_shared_key`, `wpa_key`, `network_key`, `pskc`, `master_key`, `active_operational_dataset`,
`private_key`, `secret`, `client_secret`, `api_key`, `token`, `user_token`, `access_token`,
`refresh_token`, `session_id`, `session_token`, `auth_token`, `temporary_token`,
`activation_token`, `guardian_secret`, `authentication_key`, `commissioning_credential`,
`pppoe_credentials`. Null and empty values are
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
| `authentication_required` | No session, or it expired or was revoked | Call the `login` tool or run `eero-mcp login` (or log in with `eeroctl`); the new session is picked up automatically unless `RUSTEERO_SESSION_TOKEN` is set, in which case restart with a fresh token |
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
| `login_requires_terminal` | `login` only: the client cannot show forms (no elicitation form capability in its handshake, or protocol 2026-07-28, which forbids server-to-client requests) | Run `eero-mcp login` in a terminal; the running server picks the session up. Nothing was sent to eero |
| `login_cancelled` | `login` only: a form was declined or dismissed, or not answered within 10 minutes | Nothing was saved; call `login` again when you want to sign in |
| `login_failed` | `login` only: eero refused to start the login (Amazon accounts cannot use code login), the code was rejected 3 times, eero refused the verification for another reason, a form got no usable answer, another login is in progress, or `EERO_MCP_SESSION_FILE` names the own session file | The message says which; nothing was saved. A cancelled call returns no result at all |

Type errors (an unknown input field, a wrong type, a value outside an enumeration) are reported by
the MCP SDK as plain text starting with `failed to deserialize parameters`, not in the JSON shape
above.

## Security and privacy

- **The network tools are read-only by construction.** The 40 network tools call only the 40
  catalogued rusteero read methods. A test scans the source and fails the build if any write or
  action method, a raw API request, or a credential store appears outside the one module that signs
  in and out.
- **One module signs in and out, and writes only eero-mcp's own store.** Login, logout and the
  credential-store writes live in a single source file, reachable only through a short list of
  exact rusteero paths, and only with eero-mcp's own keyring names and own file. The shared keyring
  entry, `cookies.json`, `RUSTEERO_SESSION_TOKEN` and the explicit file are never written, migrated
  or deleted, and the server's rusteero client is built with an explicit session and no credential
  store. A failed session refresh can clear only the in-memory session.
- **The token stays secret.** It is held as a secret in memory, and never logged, returned in a
  result or placed in error text. eero-mcp's own logs never carry credentials, credential file
  paths or response bodies. The login identifier and the one-time code are held as secrets too, and
  are never logged, echoed or returned. Redirects are always refused, and credentials are sent only
  to the configured eero API origin.
- **The one-time code goes through your host.** In the chat login the code travels in an MCP form
  response, so the host sees it (see [Logging in](#logging-in) for the reason and the mitigations);
  the model and the tool arguments never do. The terminal login keeps it out of the host.
- **Requests that are not GETs.** Besides the automatic session refresh below, only explicit
  operations send any:

  | Operation | Requests |
  |---|---|
  | `login` tool, `eero-mcp login` | `POST /2.2/login` (eero sends the code), `POST /2.2/login/resend` (only when you ask for a new code), `POST /2.2/login/verify` |
  | `eero-mcp login`, only when the session could not be saved | `POST /2.2/logout` for that new session, so no unsaved session stays live |
  | `eero-mcp logout` | `POST /2.2/logout`, once for each distinct session found in eero-mcp's own store and in no other source |
  | `eero-mcp status` | one `GET /2.2/account` |

  Nothing ever changes your network's settings. Each of these is sent only when you ask for it, and
  none is retried.
- **Automatic session maintenance.** When eero answers a request with a 401 carrying the
  `error.session.refresh` code, rusteero sends a single `POST /2.2/login/refresh` (authenticated by
  the current token) and replays the original request once. This is session maintenance, not a
  change to your network. The token does not rotate.
- **An agent could ask for a login.** `login` takes an optional identifier chosen by the model, so
  a prompt injection could start a login for an address you did not choose. The tool description
  limits it to a value you typed, the tool is annotated as not read-only so hosts can ask first, the
  code goes only to that address and never to the model, and eero rate-limits login starts. A login
  makes at most 3 starts, 3 resends and 3 verification attempts.
- **Your data goes only to your MCP host.** There is no network listener and no telemetry. The
  server's only outbound traffic is to the eero cloud API. Results still contain your own network
  data (device names, MAC addresses, IP addresses, the account email): that is the purpose of the
  server, and it is handed to whichever MCP host and model you connect.
- **Keep secrets out of configuration.** A token placed in a host's `env` map is stored there in
  plain text; prefer `eero-mcp login`, the keyring or a credential file.
- **Own session file permissions.** The own file is `0600` in a `0700` directory on Unix; on
  shared machines prefer the keyring (the default build), which holds the session when it works.

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

`tools/list` shows 41 tools. A `tools/call` of `login` against a local mock returns
`login_requires_terminal` (exit 5) when the Inspector's CLI declares no elicitation capability, and
sends nothing; never call `login` against the real API from a script, because a real call makes eero
send you a message.

Exit codes: 0 success, 5 an `isError` result or an unknown tool, 1 a JSON-RPC error, 6 a `--strict`
error. With `--strict`, a catalogue with no portability findings prints no report at all. Pass ids
with `--tool-args-json`: the `--tool-arg key=value` form turns numeric-looking ids into numbers.
Against a real session the output contains your real network data; do not paste or commit it.

> **Keep real tokens off the command line.** When the Inspector is started through `npx`,
> npm echoes the full command line on stderr (`npm notice run ...`), including any
> `-e RUSTEERO_SESSION_TOKEN=<token>` argument, and the shell history and process list hold it too.
> The `test-token` above is a placeholder for a local mock API. Against a real account, prefer
> `-e EERO_MCP_SESSION_FILE=/path/to/copy` (an absolute path to a copy of the credential record),
> or set the token in the MCP host's own `env` configuration, and never paste a real token into a
> command line whose output is shared or logged.

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
and read-only guard tests. The login tool is tested through an in-process MCP client that implements
elicitation, and the subcommands through the built binary against a mock eero API with scripted
stdin, a temporary configuration directory and the keyring disabled: no test touches the real
keyring or your real files, and none triggers a real login. All fixtures are synthetic, and a
tripwire fails any POST, PUT, PATCH or DELETE that a test did not expect.

The live tests (`tests/live.rs`) read the real eero cloud through a hand-written read-only
allowlist. They are `#[ignore]`d, additionally gated on `EERO_MCP_LIVE=1`, print only result codes,
top-level key names, counts and whether a credential was found (never bodies or identifiers), fail
on a malformed result or an undocumented error code, and are meant to be run by a person, never in
CI:

```bash
EERO_MCP_LIVE=1 cargo test --all-features --test live -- --ignored --nocapture
```

The live tests never include the `login` tool or the subcommands.

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
- **Amazon-login accounts** cannot use the one-time-code login; see [Logging in](#logging-in) for
  the workaround.
- **Hosts without form elicitation.** Some MCP hosts cannot show forms, and protocol 2026-07-28
  forbids server-to-client requests. The `login` tool then returns `login_requires_terminal`; use
  `eero-mcp login` in a terminal.
- **Host tool-call timeouts.** A host may end a `login` call before you have the code; see
  [Logging in](#logging-in).
- **403 and 404 on some accounts or firmware.** `get_transfer_stats` returns a 403 on some
  accounts, and some endpoints answer 404 on some firmware or networks.
- **Undocumented API.** The API is reverse-engineered and can change; data is returned as-is, so
  new or renamed fields pass through, and unexpected responses become `upstream_error`. One
  exception: if the network list arrives in an unrecognised container, it is treated as empty, so
  `list_networks` returns `[]` and omitting `network_id` returns `not_found`.
- **Names are untrusted text.** Device names and hostnames are set by the devices that join your
  network (the guest network included), and neighbouring Wi-Fi network names (SSIDs) by anyone in
  radio range. The server tells the agent to treat them as data, never as instructions, but a
  host that acts on tool results should still treat them as untrusted input.
- **Cached reads can be up to 60 seconds old.** Use `refresh: true` where a tool offers it.
- **One account per process.** Run a second server entry for a second account and give it its own
  `RUSTEERO_SESSION_TOKEN`, which wins over every other source. With the default chain both entries
  read the same own store, keyring entry or `cookies.json` and so get the same account; a usable
  `EERO_MCP_SESSION_FILE` is read before the own store, so a separate credential file also works.
  Separate own stores need separate `EERO_MCP_CONFIG_DIR` values (and `EERO_MCP_NO_KEYRING=1`, as
  there is one keyring entry per user).
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
