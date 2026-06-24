<div align="center">

# BurpMCP-Ultra

**The most powerful MCP server for Burp Suite Professional.**

Drop a single JAR into Burp, connect Claude Code (or any MCP client), and drive every
part of Burp Suite programmatically through AI agents.

[![Version](https://img.shields.io/badge/version-2.1.0-1f6feb)](https://github.com/Cy-S3c/BurpMCP-Ultra/releases)
[![License](https://img.shields.io/badge/license-MIT-3fb950)](#license)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional-ff6633)](https://portswigger.net/burp)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.1.20-7F52FF?logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-149-8957e5)](#tools)
[![Telegram](https://img.shields.io/badge/Telegram-%40D4RK__V0RT3X-2CA5E0?logo=telegram&logoColor=white)](https://t.me/D4RK_V0RT3X)

**149 Tools** &bull; **8 Resources** &bull; **17 Event Types** &bull; Real-time Dashboard &bull; Hardened Localhost Security

[Quick Start](#quick-start) &bull;
[Tools](#tools) &bull;
[Features](#highlight-features) &bull;
[Security](#security-model) &bull;
[Dashboard](#web-dashboard) &bull;
[Setup Guides](#setup-guides) &bull;
[Contact](#contact--support)

</div>

---

BurpMCP-Ultra is a native **Kotlin** Burp Suite extension with an embedded **MCP (Model
Context Protocol)** server. It exposes Burp's Montoya API as 149 structured tools over a
token-secured local SSE transport, so an AI agent can run proxy history analysis, active
scans, fuzzing, race conditions, OOB testing, custom scan checks, and guided exploitation
— all from natural language.

## Why BurpMCP-Ultra?

| | BurpMCP-Ultra | burp-ai-agent | PortSwigger Official |
|---|:---:|:---:|:---:|
| **MCP Tools** | **149** | 53 | 12 |
| **Custom Scan Checks** | BCheck + Script | – | – |
| **Guided Injection Probe** | SQLi / SSTI / LFI oracles | – | – |
| **JWT Attacks** | alg:none, RS→HS, crack | – | – |
| **Access-Control Sweep** | IDOR / privesc across identities | – | – |
| **WebSocket Testing** | Full lifecycle | – | – |
| **Inline Fuzzer** | 3 modes (FUZZ / Marker / Offset) | – | – |
| **Race Condition Testing** | Single-packet attack | – | – |
| **API Schema Import** | OpenAPI / Swagger + `$ref` | – | – |
| **Passive Intel Extraction** | 30+ patterns, entropy de-noised | – | – |
| **Recon** | JS endpoints, content/param discovery | – | – |
| **Real-time Dashboard** | Web + Swing | – | – |
| **Hardened Localhost Security** | Host + Origin + token, scope gate | – | – |
| **Collaborator OOB** | Full create / poll / correlate | Partial | Partial |

> Competitor counts are indicative, based on each project's public tool list.

---

## Quick Start

### 1. Build

```bash
git clone https://github.com/Cy-S3c/BurpMCP-Ultra.git
cd BurpMCP-Ultra
./gradlew shadowJar
```

Output: `build/libs/burpmcp-ultra-2.1.0.jar` (~13 MB). A **JDK 17–21** must be installed —
see [Building from Source](#building-from-source). Pre-built JARs are on the
[Releases](https://github.com/Cy-S3c/BurpMCP-Ultra/releases) page.

### 2. Load into Burp

1. Burp Suite Pro → **Extensions** → **Add**
2. Select the JAR
3. The **BurpMCP-Ultra** tab appears with a green "Running" status and your connection token

### 3. Connect Claude Code

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/",
      "headers": {
        "Authorization": "Bearer PASTE_TOKEN_FROM_SERVER_TAB"
      }
    }
  }
}
```

Add to `~/.claude.json` or your project's `.mcp.json`.

> ⚠️ **The token is required, and the endpoint is the root path `/` — not `/sse`.**
> Copy the token from the **Server** tab of the BurpMCP-Ultra panel in Burp (it is also
> accepted as a `?token=…` query parameter or an `mcp_token` cookie). Without it the
> server returns `401`, and clients like Claude Code then fall back to OAuth discovery and
> fail with `SDK auth failed: HTTP 404: Invalid OAuth error response`.

### 4. Open Dashboard

Browse to **http://127.0.0.1:9878** for the real-time web dashboard.

---

## Tools

**149 MCP tools** across 36 categories. Names are stable; the authoritative count is
`server.tools.size`, surfaced in the Server tab.

### Proxy (13)
| Tool | Description |
|------|-------------|
| `proxy_history` | Get HTTP proxy history with filtering (host, method, status, MIME, scope) |
| `proxy_history_search` | Regex search across proxy history (URL, headers, body) |
| `proxy_websocket_history` | Get WebSocket proxy history |
| `proxy_websocket_history_search` | Regex search WebSocket history |
| `proxy_intercept_enable` / `proxy_intercept_disable` / `proxy_intercept_status` | Control & inspect interception |
| `proxy_annotate` | Add highlight color and comment to a history item |
| `proxy_set_request_rule` / `proxy_set_response_rule` | Auto modify/drop/tag matching proxy traffic |
| `proxy_list_rules` / `proxy_remove_rule` | Manage proxy rules |
| `proxy_auto_auth` | One-command auth-header injection for all matching requests |

### HTTP (13)
| Tool | Description |
|------|-------------|
| `http_send_request` | Send HTTP request (structured or raw, HTTP/1.1 or HTTP/2) |
| `http_send_requests_parallel` | Send multiple requests in parallel (batch ops, races) |
| `http_send_request_chain` | Multi-step request sequence with token extraction between steps |
| `http_send_raw_bytes` | Byte-level request for smuggling and CRLF injection |
| `http_fuzz` | Inline fuzzer — FUZZ keyword, `§marker§`, or byte-offset modes + payload libraries |
| `http_race` | Race-condition testing — fire N requests simultaneously |
| `http_cookie_jar_get` / `http_cookie_jar_set` | Read/write Burp's cookie jar |
| `http_analyze_keywords` | Analyze a response for keyword occurrences |
| `http_analyze_variations` | Detect response variations (blind injection) |
| `http_set_traffic_rule` / `http_list_traffic_rules` / `http_remove_traffic_rule` | Global request/response rules |

### Scanner (13)
| Tool | Description |
|------|-------------|
| `scanner_start_crawl` | Start a web crawl from seed URLs |
| `scanner_start_audit` | Start active/passive scan with optional auth config |
| `scanner_task_status` / `scanner_task_list` / `scanner_task_delete` | Manage scan/crawl tasks |
| `scanner_task_add_request` | Add a request to a running audit |
| `scanner_task_issues` | Get issues from a specific task |
| `scanner_get_all_issues` | All issues with severity/confidence filter |
| `scanner_generate_report` | Generate HTML/XML scan report |
| `scanner_create_issue` | Create a custom audit issue |
| `scanner_import_bcheck` | Import a BCheck script for custom scanning |
| `scanner_register_check` / `scanner_unregister_check` | Register / deregister a custom scan check |

### Collaborator (7)
| Tool | Description |
|------|-------------|
| `collaborator_create_client` | Create a Collaborator client for OOB testing |
| `collaborator_restore_client` | Restore a client from its secret key |
| `collaborator_generate_payload` | Generate a Collaborator payload |
| `collaborator_default_payload` | Generate a payload on a shared default client (quick OOB) |
| `collaborator_poll` | Poll for DNS / HTTP / SMTP interactions (decodes DNS qnames) |
| `collaborator_server_info` | Get the Collaborator server address |
| `collaborator_get_secret` | Get the client secret key for session persistence |

### Intruder & Repeater (4)
| Tool | Description |
|------|-------------|
| `intruder_send` / `intruder_send_with_positions` | Send to Intruder (auto or explicit positions) |
| `intruder_register_payload_processor` | Register a custom payload processor |
| `repeater_send` | Send a request to a Repeater tab |

### WebSocket (7)
| Tool | Description |
|------|-------------|
| `websocket_create` | Create a WebSocket connection |
| `websocket_send_text` / `websocket_send_binary` | Send text / binary messages |
| `websocket_close` / `websocket_list` | Close / list connections |
| `websocket_get_messages` | Get messages with a direction filter |
| `websocket_set_intercept_rule` | Auto-intercept WebSocket messages |

### Offensive & Recon (11)
| Tool | Description |
|------|-------------|
| `injection_probe` | Guided **SQLi / SSTI / LFI** with confirmation oracles (SQL-error fingerprints, time-delay, template math-eval, file markers) — not blind fuzzing |
| `jwt_attack` | JWT offense — `alg:none`, **RS→HS** key confusion, weak-secret cracking, structural analysis |
| `access_control_sweep` | Batch **broken-access-control / IDOR** across multiple identities |
| `graphql_probe` | GraphQL **introspection** + field-suggestion enumeration |
| `cors_probe` | Detect **CORS** misconfigurations (reflected / null origin, credentialed) |
| `recon_fingerprint` | Technology + WAF fingerprinting |
| `recon_js_endpoints` | Harvest endpoints/URLs from JavaScript files |
| `recon_content_discovery` | Path / content discovery against a target |
| `recon_param_mine` | Mine hidden & reflected parameters |
| `findings_add` / `findings_list` | The agent's deduplicated working store of findings |

> Offensive tools that issue live requests are **scope-gated** (see [Security](#security-model)).

### Analysis (7)
| Tool | Description |
|------|-------------|
| `analyze_request` / `analyze_response` | Parse HTTP messages into structured components |
| `analyze_find_reflected` | Find parameter values reflected in a response (XSS surface) |
| `analyze_extract_params` | Extract all parameters (URL, body, cookie, header, JSON) |
| `analyze_insertion_points` | Scanner-style insertion points (incl. JSON-body leaves) |
| `analyze_diff` | Compare two requests or responses |
| `analyze_response_body_search` | Search all proxy response bodies for a pattern |

### Advanced Analysis (3)
| Tool | Description |
|------|-------------|
| `auth_diff` | Compare responses across auth levels → IDOR / privesc verdict |
| `api_import_openapi` | Import OpenAPI/Swagger (with `$ref` resolution), generate requests, populate sitemap |
| `passive_intel` | Extract secrets/tokens/IPs from proxy history — 30+ patterns, entropy de-noised |

### Utilities (12)
| Tool | Description |
|------|-------------|
| `util_url_encode` / `util_url_decode` | URL encoding / decoding |
| `util_base64_encode` / `util_base64_decode` | Base64 encoding / decoding |
| `util_html_encode` | HTML entity encoding |
| `util_hash` | Hashing (MD5, SHA1, SHA256, SHA384, SHA512) |
| `util_compress` / `util_decompress` | Gzip / deflate / brotli |
| `util_random_string` / `util_random_bytes` | Random generators |
| `util_jwt_decode` | Decode a JWT (header, payload, expiry) |
| `util_decode_smart` | Auto-detect and decode multi-layer encoding |

### Custom Scan Checks — BCheck (5) + Script (5)
| Tool | Description |
|------|-------------|
| `bcheck_create` | Generate & deploy a BCheck from structured parameters |
| `bcheck_import` | Import a raw BCheck DSL script |
| `bcheck_templates` / `bcheck_list` / `bcheck_remove` | Templates, list, remove BChecks |
| `scancheck_create_passive` | Passive check with multi-condition matching |
| `scancheck_create_active` | Multi-step active check with payload chains |
| `scancheck_templates` / `scancheck_list` / `scancheck_remove` | Templates, list, deregister script checks |

### Scope & Sitemap (8)
| Tool | Description |
|------|-------------|
| `scope_check` / `scope_include` / `scope_exclude` / `scope_get_config` | Target scope management |
| `sitemap_query` / `sitemap_get_issues` / `sitemap_add_request` / `sitemap_add_issue` | Sitemap operations |

### Config & Burp (16)
| Tool | Description |
|------|-------------|
| `burp_version` | Burp version and edition |
| `burp_export_project_config` / `burp_import_project_config` | Project config as JSON |
| `burp_export_user_config` / `burp_import_user_config` | User config as JSON |
| `burp_task_engine_state` / `burp_task_engine_set` | Pause/resume all background tasks |
| `burp_command_line_args` | Startup arguments |
| `burp_shutdown` | Shut down Burp (gated — see [Security](#security-model)) |
| `config_proxy_listeners_list` / `config_proxy_listener_add` / `config_proxy_listener_remove` | Manage proxy listeners |
| `config_match_replace_add` / `config_match_replace_list` / `config_match_replace_remove` | Manage match-and-replace rules |
| `config_upstream_proxy_set` | Configure an upstream proxy (Tor, corporate) |

### Platform (25)
| Tool | Description |
|------|-------------|
| `session_create_token_rule` / `session_list_rules` / `session_remove_rule` | Session-handling rules (extract → inject) |
| `events_get` / `events_get_by_type` / `events_subscribe` / `events_unsubscribe` / `events_clear` | Event system |
| `persistence_store` / `persistence_get` / `persistence_delete` / `persistence_list` | Project data storage |
| `preference_store` / `preference_get` | Global preferences |
| `decoder_send` / `comparer_send` | Send to Decoder / Comparer |
| `organizer_send` / `organizer_get_items` | Organizer management |
| `log_message` / `log_event` | Burp logging |
| `ai_status` / `ai_prompt` | Burp AI integration (Burp 2025+) |
| `bambda_import` | Import Bambda scripts |
| `project_info` / `extension_info` | Project & extension metadata |

### Resources (8)
Read-only MCP resources an agent can fetch without a tool call:
`burp://proxy/history` · `burp://proxy/websocket/history` · `burp://scanner/issues` ·
`burp://sitemap` · `burp://scope` · `burp://config/project` · `burp://config/user` ·
`burp://organizer/items`

---

## Highlight Features

### Guided Injection Probe
```
injection_probe(
  request: "GET /item?id=FUZZ HTTP/1.1\r\nHost: shop.com\r\n\r\n",
  host: "shop.com", port: 443,
  classes: ["sqli", "ssti", "lfi"]      # optional; default all
)
```
Marks the injection point with `FUZZ`, then **confirms** vulnerabilities with deterministic
oracles — SQL error fingerprints, time-delay analysis, template math-evaluation
(`1337*1337 → 1787569`), and file-content markers — returning only confirmed findings with
the triggering payload. For blind/OOB classes, pair `collaborator_*` with `http_fuzz`.

### JWT Attacks
```
jwt_attack(token: "eyJ...", mode: "crack", wordlist: ["secret", "changeme", ...])
```
`alg:none` forgery, **RS→HS** algorithm-confusion forging, weak-secret dictionary cracking,
and full structural analysis.

### Access-Control Sweep
```
auth_diff / access_control_sweep
  request: "GET /api/users/1 HTTP/1.1\r\nHost: api.com\r\n\r\n",
  auth_levels: [
    {"name": "admin", "header_name": "Authorization", "header_value": "Bearer admin"},
    {"name": "user",  "header_name": "Authorization", "header_value": "Bearer user"},
    {"name": "none"}
  ]
```
Replays the same request(s) across identities, diffs the responses, and flags **IDOR**,
privilege escalation, and missing authorization.

### Race Condition Testing
```
http_race(request: "POST /api/transfer HTTP/1.1\r\nHost: bank.com\r\n\r\n{\"amount\":100}",
          host: "bank.com", port: 443, count: 20)
```
Fires 20 identical requests simultaneously via Burp's parallel engine and analyzes
status/length distributions to detect TOCTOU, double-spend, and limit-bypass bugs.

### Inline Fuzzer (3 modes)
```
# FUZZ keyword
http_fuzz(request: "GET /api?id=FUZZ HTTP/1.1\r\nHost: api.com\r\n\r\n", host: "api.com",
          port: 443, payloads: ["1", "admin", "../../etc/passwd"])
# §section§ markers (like Intruder)   |   # byte offsets: positions: [[12, 15]]
# built-in payload libraries via:     payload_library: "xss" | "sqli" | "lfi" | ...
```

### Custom Scan Checks
```
# BCheck DSL
bcheck_create(name: "AWS Key Leak", type: "passive_response",
              match_pattern: "AKIA[0-9A-Z]{16}", severity: "high", confidence: "firm")
# Script mode — multi-step active check
scancheck_create_active(name: "SSTI", steps: [
  {"payload": "{{7*7}}", "response_conditions": [
    {"location": "response_body", "pattern": "49", "condition_type": "contains"}]}])
```

### API Schema Import
```
api_import_openapi(spec_json: "<swagger/openapi JSON>", auth_header: "Authorization",
                   auth_value: "Bearer …", send_requests: true, add_to_sitemap: true)
```
Parses OpenAPI 3.x / Swagger 2.0 (resolving `$ref`), generates real requests with sample
parameters/bodies for every endpoint, and optionally sends them — populating proxy history
and sitemap. Out-of-scope sends are skipped and reported.

### Passive Intelligence Extraction
```
passive_intel(max_items: 2000, in_scope_only: true)
```
Scans captured traffic for 30+ patterns with entropy de-noising to cut false positives:
- **Cloud credentials** — AWS keys, Google/Slack/Stripe/GitHub tokens
- **Tokens & secrets** — JWTs, Bearer/Basic auth, private keys
- **Personal data** — emails, internal IPs, phone numbers
- **Cloud resources** — S3/Azure/GCS buckets
- **Infrastructure** — internal URLs, GraphQL endpoints, API paths
- **Errors & fingerprints** — stack traces, SQL errors, server/framework versions
- **Sensitive paths** — `/admin`, `/.env`, `/.git`, `/debug`, `/actuator`

---

## Security Model

BurpMCP-Ultra runs three local servers (SSE `9876`/`9877`, dashboard `9878`). Binding to
`127.0.0.1` is **not** a trust boundary, so the transport is hardened and offensive tools are
governed by **operator-only** controls the agent cannot change.

**Transport hardening**
- **Host-header allowlist** — defeats DNS rebinding.
- **Origin lockdown** — rejects cross-origin browser requests; CORS only advertises loopback.
- **Per-session token** — required on every request (`Authorization: Bearer`, `mcp_token`
  cookie, or `?token=`). The dashboard uses an `HttpOnly` cookie, so the token never lives in a URL.

**Operator governance** (configured in Burp, not via MCP)
- `mcp_scope_mode` — `off` / `warn` / `enforce`. Every live-request tool passes through a
  central **scope gate** (`http_*`, `auth_diff`, `api_import_openapi`, `recon_*`, `graphql_probe`,
  `cors_probe`, `access_control_sweep`, `injection_probe`).
- `mcp_allow_destructive` — default **false**; blocks `burp_shutdown` and config import.
- **Append-only audit log** of security-relevant tool calls (`~/.burpmcp-ultra-audit.jsonl`).

Additional defenses: ReDoS-safe regex, CRLF header validation, and response/WebSocket size caps.

---

## Web Dashboard

Open **http://127.0.0.1:9878** for the real-time dashboard:

- **Live Activity Stream** with noise filtering (auto-hides Google/Apple/Microsoft connectivity checks)
- **Attack Vector Detection** — badges for AUTH, API, PARAMS, UPLOAD, ADMIN, DATA endpoints
- **Request Detail Panel** — click any item for full request info + send-to-tool actions
- **Stats Bar** — live counters for events, in-scope hosts, and attack-vector categories
- **Filter Controls** — type filters, URL search, noise toggle
- **Active Rules** — view all proxy, traffic, and session rules
- **Connection Info** — transport URLs and a ready-to-paste MCP client config

---

## Setup Guides

<details>
<summary><strong>Claude Code (Direct SSE)</strong></summary>

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876/",
      "headers": { "Authorization": "Bearer PASTE_TOKEN_FROM_SERVER_TAB" }
    }
  }
}
```
The token comes from the **Server** tab. The endpoint is the root path `/` (not `/sse`); the
token may instead be passed as `?token=…` or an `mcp_token` cookie. Config locations:
`~/.claude.json` (global) or `.mcp.json` (per-project).

</details>

<details>
<summary><strong>Claude Code via Caddy (recommended for stability)</strong></summary>

Caddy prevents SSE timeout disconnections and provides reliable buffering.

```bash
sudo apt install caddy
```
`/etc/caddy/Caddyfile`:
```
:9900 {
    reverse_proxy 127.0.0.1:9876 {
        transport http { read_timeout 0  write_timeout 0  response_header_timeout 0 }
        flush_interval -1
        header_up Connection {>Connection}
        header_up Upgrade {>Upgrade}
    }
}
```
```bash
sudo systemctl restart caddy
```
Then point your config at port 9900:
```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9900/",
      "headers": { "Authorization": "Bearer PASTE_TOKEN_FROM_SERVER_TAB" }
    }
  }
}
```
Pre-built Caddyfile: [`configs/Caddyfile`](configs/Caddyfile)

</details>

<details>
<summary><strong>Claude Desktop (stdio via proxy)</strong></summary>

Claude Desktop only supports stdio transport. Bridge it with supergateway:
```json
{
  "mcpServers": {
    "burp": {
      "command": "npx",
      "args": ["-y", "supergateway", "--sse", "http://127.0.0.1:9876/", "--header", "Authorization: Bearer PASTE_TOKEN_FROM_SERVER_TAB"]
    }
  }
}
```

</details>

<details>
<summary><strong>Automated setup script</strong></summary>

```bash
chmod +x configs/setup.sh
./configs/setup.sh
```
Builds the JAR, optionally configures Caddy, and prints the MCP config to add.

</details>

---

## Architecture

```
+---------------------------------------------------+
|                BURP SUITE PRO                      |
|  +---------------------------------------------+  |
|  |        BurpMCP-Ultra Extension              |  |
|  |                                             |  |
|  |  Montoya API --> Bridge Layer (32 bridges)  |  |
|  |       |                |                    |  |
|  |  Event Bus    Tool Registry (149 tools)     |  |
|  |       |                |                    |  |
|  |       +------- MCP Server Core -------+     |  |
|  |               (Kotlin SDK 0.8.3)      |     |  |
|  |                    |                  |     |  |
|  |         +----------+----------+       |     |  |
|  |     SSE :9876  SSE :9877  Dashboard   |     |  |
|  |                            :9878      |     |  |
|  +---------------------------------------------+  |
+---------------------------------------------------+
```

## Tech Stack

| Component | Version |
|-----------|---------|
| Kotlin | 2.1.20 |
| JVM Target | 17 |
| Montoya API | 2026.2 |
| MCP Kotlin SDK | 0.8.3 |
| Ktor CIO | 3.2.3 |
| kotlinx.serialization | 1.8.1 |
| Shadow JAR | 8.1.1 |

## Requirements

**To run (inside Burp):**
- Burp Suite Professional 2025.x or later
- Java 17+ — provided by Burp's bundled JRE (nothing to install)

**To build from source:**
- A **JDK 17–21** (LTS) installed. Building under Java 22+ (including Burp's bundled Java 25)
  is incompatible with the Kotlin 2.1.20 / Ktor 3.2.3 / MCP SDK toolchain and yields a JAR
  whose MCP SSE ports silently fail to bind. You do **not** need JDK 17 as your default,
  though: the build pins both compilation and the Gradle daemon to a JDK 17 toolchain
  (`gradle/gradle-daemon-jvm.properties`), so `./gradlew` auto-runs under JDK 17 as long as
  one is installed and discoverable.
- Gradle 8.x — included via the committed wrapper (`./gradlew` / `gradlew.bat`).

## Building from Source

The Gradle wrapper is committed, so no separate Gradle install is needed.

**Linux / macOS**
```bash
git clone https://github.com/Cy-S3c/BurpMCP-Ultra.git
cd BurpMCP-Ultra
# Gradle auto-selects an installed JDK 17 for the build daemon, so this works even if your
# default `java` is Burp's Java 25. If no JDK 17 is discoverable, install one (or set JAVA_HOME).
./gradlew shadowJar
# Output: build/libs/burpmcp-ultra-2.1.0.jar
```

**Windows (PowerShell / cmd)**
```bat
git clone https://github.com/Cy-S3c/BurpMCP-Ultra.git
cd BurpMCP-Ultra
:: Gradle auto-selects an installed JDK 17 for the build daemon, so this works even if your
:: default java is Burp's Java 25. If no JDK 17 is discoverable, install one (or set JAVA_HOME).
gradlew.bat shadowJar
:: Output: build\libs\burpmcp-ultra-2.1.0.jar
```

> If no JDK 17 is found, Gradle fails with a clear "no compatible daemon JVM" error instead of
> silently producing a broken JAR. Kotlin 2.1.20 cannot even *compile* the Gradle build scripts
> under Java 22+, which is why the daemon is pinned to JDK 17.

## Project Structure

```
BurpMCP-Ultra/
├── build.gradle.kts              # Build configuration
├── gradle/                       # Wrapper + daemon-JVM pin (JDK 17)
├── configs/                      # Ready-to-use config files (Caddyfile, MCP JSON, setup.sh)
├── src/main/kotlin/com/burpmcp/ultra/
│   ├── core/                     # Extension entry point + helpers
│   ├── bridge/                   # 32 Montoya API bridges
│   ├── tools/                    # 36 tool category modules (149 tools)
│   ├── safety/                   # Scope gate, action policy, ReDoS-safe regex
│   ├── transport/                # MCP server + dashboard + security
│   ├── events/                   # Unified event bus
│   ├── state/                    # State management
│   └── ui/                       # Swing UI tab
├── src/test/                     # 105 unit tests
└── docs/                         # Tool catalog + capability review
```

---

## Contact & Support

- 🐛 **Bugs & feature requests:** [GitHub Issues](https://github.com/Cy-S3c/BurpMCP-Ultra/issues)
- 📦 **Releases & changelog:** [GitHub Releases](https://github.com/Cy-S3c/BurpMCP-Ultra/releases)
- 💬 **Quick reach:** Telegram [**@D4RK_V0RT3X**](https://t.me/D4RK_V0RT3X)

## License

[MIT](LICENSE)

---

<div align="center">
Built for bug-bounty hunters and pentesters who want AI-powered Burp Suite automation.
</div>
