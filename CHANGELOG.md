# Changelog

All notable changes to BurpMCP-Ultra are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/) (see `docs/ROADMAP.md` for the semver convention).

## [2.3.1] — 2026-09-16 — The agent's findings, rendered in Burp — and durable

Theme: a native **Findings** tab that shows what the agent records via `findings_add`, a durable
per-project findings store so that memory survives reloads, richer finding fields (CVSS, OWASP Top 10
2021, steps, request/response evidence), and fixes for the Proxy Explorer / Scanner tabs — including
the "search always returns 0 rows" bug most plausibly behind [discussion #16](https://github.com/Cy-S3c/BurpMCP-Ultra/discussions/16).

### Added
- **Findings tab (tab #4)** — the agent's deduplicated findings working memory, rendered natively in
  Burp: a severity/CVSS color-coded table (ID, Severity, CVSS, Type, OWASP 2021, URL, Location,
  Created), a detail pane with the full record, and **request/response evidence in Burp-native
  read-only editors**. Severity filter (**including Critical**), free-text search (type / URL /
  location / detail / OWASP), right-click Copy URL / Copy Finding JSON / Delete Finding, and a
  confirmed Clear All. The tab live-updates when the agent records findings (1.5 s refresh, rebuild
  only on change so an operator's selection is never reset) and refreshes on tab selection.
- **Durable findings store** (`~/.burpmcp-ultra-findings.jsonl`) — findings used to live only in
  memory and were wiped by `StateManager.cleanup()` on every extension reload / Burp restart, while
  the (persisted) MCP activity log still *showed* the historical `findings_add` calls — making it
  look like findings vanished for no reason. New `FindingsStore` mirrors `ActivityStore`: JSON
  Lines, appended per entry, **project-tagged**, multi-project-safe rewrites on delete/clear,
  restored on startup with the shared id counter continued past restored suffixes so new ids never
  collide. Agent adds persist via a listener; operator deletes rewrite the store.
- **Richer `findings_add`** — six new optional fields:
  - `cvss_score` — validated (blank or 0.0–10.0; anything else returns an actionable error)
  - `cvss_vector` — e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  - `owasp_category` — **normalized to canonical OWASP Top 10 2021** (`A03`, `a03:2021`,
    `injection`, `SSRF`, `broken access control` → `A03:2021 - Injection` etc.); unrecognized
    values pass through unchanged; the valid list is embedded in the tool schema
  - `steps_to_reproduce`, `request`, `response` — raw evidence, rendered in the tab's editors
    (truncated at 4 000 chars in `findings_list` output)
- **Critical severity** in the Findings tab filter and the shared severity renderer.

### Fixed
- **Proxy Explorer: Search always returned 0 rows.** The Search action read `result["matches"]`, a
  key `searchHistory` never emits (it returns `items`, with only the *count* named
  `total_matches`) — so every search silently emptied the table. A failed search now also surfaces
  its error instead of looking identical to "no matches".
- **Proxy Explorer: HTTP traffic was shown (and sent) as HTTPS.** The detail viewer and the
  Send-to-Repeater/Intruder actions read `item["is_tls"]`, which the serializer never emits (the
  key is `secure`); the fallback defaulted every miss to TLS, so plain-HTTP items rendered with an
  `https://` service and failed when sent. Now reads `secure`, falling back to port-based inference.
- **Proxy Explorer: history-cache race** — the cache was cleared on the worker thread while the
  table rebuilt later on the EDT; both now rebuild together inside the EDT block.
- **Scanner: Host column was always blank** — the UI read `issue["host"]`, which `serializeIssue`
  never emits; the host is now derived from the issue's base URL.
- **Scanner: issue evidence was serialized but never shown** — the detail pane is now tabbed
  (Details + **Request Evidence**), rendering the first `request_responses` pair in a Burp-native
  read-only request editor.
- **`http_send_request(raw_request=…)` still kettled on LLM bare-LF output** — the final [#7](https://github.com/Cy-S3c/BurpMCP-Ultra/issues/7)
  gap: 2.3.0 normalized CRLF in the repeater/intruder/organizer/sitemap/analysis builders but left
  the raw-request path of `http_send_request` verbatim, straight into the same
  `HttpRequest.httpRequest(service, string)` call that folds a bare-LF message into the HTTP/2
  `:path`. `buildFromRawRequest` now normalizes LF→CRLF **before** `fixContentLength` (which keys
  on `\r\n\r\n` and silently no-ops on bare-LF input). Lossless for deliberate CRLF — smuggling
  research keeps its `\r\n`, and `http_send_raw_bytes` remains byte-verbatim by design.

## [2.3.0] — 2026-08-05 — IDOR hunting, header-less clients & a 33-bug QA sweep

Theme: a new IDOR capability, MCP clients that could never connect can now connect, and the backlog
of tool bugs found by a full live QA sweep. Includes the first community-contributed fix.

### Added
- **`idor_hunt` — horizontal object-id IDOR with canary confirmation (tool #150).**
  The object-id swap that `auth_diff` / `access_control_sweep` deliberately do not do: those
  vary the *auth identity* while holding the object reference constant (great for vertical /
  unauthenticated access control). `idor_hunt` additionally **swaps the object id across
  identities** and, for every (reader, owner) pair, asserts the **owner's canary** appears in the
  reader's response — a **confirmed cross-user read** — while filtering the dominant own-data-
  reflection false positive. It auto-detects the id in path/query/body/header/cookie and classifies
  the format (int / uuid v1·v4·v7 / MongoDB ObjectID / snowflake / md5·sha1·sha256 / base64 / gid),
  runs the identity-diff (vertical/unauth) for free, and can replay a bounded id-transformation set
  (encodings, neighbours, type-juggling). Scope-gated (`mcp_scope_mode`) and bounded like every
  other send. New pure engine `IdorHunt` (**+23 unit tests**) + `IdorHuntBridge`.
- **Combined IDOR methodology** — the tool and its companion `burp-idor` Claude skill are built on a
  lossless union of every IDOR/BOLA/BFLA source on the author's system (a dedicated 25-file
  idor-agent KB, the auth-authz skill's 9-part authz-deep set, and the API/auth/business-logic
  agents): **790 extracted techniques → 312 deduplicated across 30 categories**, with completeness-
  critic gap-fills (HTTP/2 desync as auth-context inheritance, gRPC field-number tampering,
  per-message WebSocket authz, gateway trusted-header forgery, second-order/async IDOR, cache-key
  mixing, cross-protocol object diffing).
- **Token-in-path auth for MCP clients that cannot set headers (issue #11).** The SSE endpoint is
  now also mounted at `http://host:port/<token>/`, so a client that accepts only a URL can connect
  with **no `headers` block at all**. The Server tab gained a **"Copy No-Headers Config"** button
  and the dashboard shows the same form.

  This is a real interop fix, not a convenience: such clients previously had **no working
  configuration**. The documented `?token=…` alternative only half-worked — it authenticated the
  SSE `GET`, then every message `401`'d, because the SDK advertises its back-channel as the
  relative reference `?sessionId=…`, which per RFC 3986 §5.3 **replaces the query but preserves the
  path**. The token therefore has to ride in the path to survive. Keep the trailing slash: Java's
  RFC 2396 `URI.resolve` drops the final segment without it (an mcp-proxy would then `401`).
  The token stays **mandatory** — it is the only control stopping any local process from driving
  Burp; the header form remains preferred where supported, since a URL-borne token is more exposed.
- **Configurable listening ports.** `mcp_sse_port` / `mcp_http_port` / `mcp_dashboard_port`
  (or `-Dburpmcp.ssePort` / `.httpPort` / `.dashboardPort`), resolved on the same ladder as the bind
  host: system property, else preference, else the 9876/9877/9878 defaults. An unparseable or
  out-of-range value falls back instead of failing startup.

  This exists because **PortSwigger's own "MCP Server" extension also defaults to 9876**: anyone
  running both extensions had an unavoidable clash and no way out of it.

### Changed
- **Native UI redesign** — a cohesive dark + crimson brand across the Burp extension tabs: a branded
  gradient header, structured crimson section headers, styled tables (crimson headers, clean
  selection), themed buttons/inputs, and a consistent palette + spacing. Burp's own request/response
  editors are left untouched so they keep matching Burp's theme. (`UiTheme`)

### Fixed
- **`sitemap_add_issue` / `scanner_create_issue` threw a `NullPointerException` whenever
  request/response evidence was attached** — *community contribution*: PR #13, reported, diagnosed
  and fixed by **@aconstantinou-cmd**, verified live on Burp Suite Professional 2026.7.1. The
  evidence `HttpRequest` was built with **no `HttpService`**, so Montoya had no host to resolve when
  filing the issue into the site map — surfacing as `Cannot invoke "burp.Zp42.hashCode()" because
  the return value of "burp.Zrio.ZWy()" is null`. Host/port/TLS are now derived from the issue's own
  `url` and attached, matching the pattern already used by `addRequestToTask`.

  Follow-up hardening on merge: the derivation was duplicated in both bridges with the two copies
  disagreeing on how a malformed URL was reported, so it now lives once in `ServiceParts.fromUrl`
  (**+11 tests**) and fails identically everywhere — an unparseable or host-less URL yields an
  actionable message instead of a raw `URISyntaxException`.
- **`proxy_history` could return JSON that no strict parser could read** (issue #12, reported with a
  full diagnosis by **@th0t3p**). With `include_response=true` the raw response was string-converted
  straight into the JSON. For a binary body — a webfont, image, archive — that yields an **unpaired
  surrogate**, which has *no UTF-8 encoding*, so the encoded stream is corrupt and the client dies
  with `Unterminated string`. Because one bad item breaks the array around it, **a single binary
  asset made an entire ~4 MB, 50-item batch unparseable**.

  Bodies now go through `BodyText`: a binary body is replaced by a short placeholder stating its
  size and MIME type (flagged as `response_binary: true`), and anything emitted as text is stripped
  of unpaired surrogates and truncated **on a safe boundary** — the old fixed-count `take()` could
  itself split a surrogate pair and manufacture the very sequence that breaks the stream. Applied to
  all four affected paths, not just the reported one: history **request** bodies (file uploads),
  history **response** bodies, and both WebSocket **payload** fields. Control characters are
  deliberately left alone — a conformant encoder escapes those correctly, and stripping them would
  corrupt legitimate text. (**+17 tests**)
- **A port clash was reported as the wrong problem.** When 9876 was already taken, the only message
  said the transport "reported start() but is NOT listening… almost always a JAR built with Java
  22+" — sending operators to rebuild their JAR when the real cause was another process (very
  plausibly PortSwigger's MCP Server extension) holding the port. The likely story behind issue #9.
  Startup now pre-checks the port and, on a clash, says plainly that it is **already in use**, that
  this is **not** the Java-version problem, names the official MCP Server extension when the port is
  its 9876 default, suggests a full Burp restart for an orphaned socket, offers `ss -ltnp | grep
  <port>` to find the owner, and names the preference that moves the port. (**+9 tests**)
- **HTTP/2 "kettled" requests / `RST_STREAM` PROTOCOL_ERROR (issue #7, reopened)** — a stray CR/LF in
  an LLM-supplied `url`, method, or header value could reach the HTTP/2 `:path` (the url-only path
  passed the raw URL straight to Montoya's `httpRequestFromUrl`) and get the request rejected by the
  server. `http_send_request` (and its `_parallel` / `_chain` siblings) now **strip control chars
  from the structured inputs** before building the request; `raw_request` / `http_send_raw_bytes`
  stay verbatim so intentional CRLF (request-smuggling research) still works. (`RequestHygiene.stripControl`)
- **`repeater_send` (and siblings) produced a "kettled" HTTP/2 request — issue #7, request-line
  variant.** A raw request with **bare-LF line endings** (what LLMs commonly emit) reached
  `HttpRequest.httpRequest(service, string)` unnormalized; Montoya could not delimit the request line,
  so the whole message folded into the HTTP/2 `:path` pseudo-header ("There is a newline in this
  header's value: :path") and the request landed in Repeater unsendable. The `#7` fix had only covered
  the *structured* `http_send_request` inputs, not the *raw-request-string* builders. Line-ending
  **normalization to CRLF is now applied** across `repeater_send`, `intruder_send`,
  `intruder_send_with_positions` (with byte-offset re-mapping so payload positions stay aligned),
  `organizer_send`, `sitemap_add_request` / `sitemap_add_issue`, `analyze_insertion_points`, and the
  injection probe; `websocket_create` strips control chars from the interpolated path/headers. Raw-byte
  tools (`http_send_raw_bytes` / `raw_request`) still pass through verbatim for smuggling research.
  (`RequestHygiene.normalizeCrlf` / `adjustedOffset`, one source of truth reused by `AnalysisBridge`, **+6 tests**)
- **`collaborator_generate_payload` crash on long/decorated custom data** — Montoya's
  `CollaboratorClient.generatePayload(customData)` rejects any label longer than 16 chars or
  containing non-alphanumerics with a raw `IllegalArgumentException` ("Length of custom data must
  not exceed 16 alphanumeric characters"), which leaked to the client and spammed the extension
  error log. The tool now **sanitizes the label to fit** (strips non-alphanumerics, truncates to 16)
  and returns a `warning` plus the `custom_data` actually embedded, so an over-long correlation
  label degrades gracefully instead of failing the call; an all-non-alphanumeric label returns a
  clean actionable error. (`CollaboratorBridge.sanitizeCustomData`, **+8 tests**)
- **32 tool bugs from a full 149-tool live QA sweep** (each reproduced against `ginandjuice.shop`,
  fixed, and unit-tested — **+167 tests**). Highlights:
  - `analyze_*` now normalize **LF→CRLF** before parsing, so LF-delimited requests (what the MCP
    transport delivers) no longer parse with `header_count: 0` / no params; empty input returns a
    clean error instead of leaking a `StringIndexOutOfBounds`.
  - The three `config_*` write tools (**match-replace**, **proxy-listener**, **upstream-proxy**) now
    emit Burp's correct (nested) JSON schema instead of always failing.
  - `http_cookie_jar_set` no longer **transposes domain/path**; `http_fuzz` honors custom markers +
    UTF-8 payloads + rejects bad offsets; `organizer_get_items`, `bcheck_create`, `graphql_probe`,
    `websocket_*` (bounded `ws://`, correct close/lookup), `api_import_openapi`, `bambda_import`
    (reports compile failures), `scanner_generate_report` (blank/dir path → generated filename).
  - Many input-validation leaks fixed (empty input, negative counts/indexes, invalid enums →
    actionable errors instead of raw JVM exceptions).

### Security
- **Unauthenticated `OPTIONS` could open an MCP SSE stream and disclose a live session id.** Two
  long-standing defects combined: the auth interceptor short-circuited on `OPTIONS` **before** the
  Host allowlist, the Origin lockdown *and* the token check; and Ktor's no-path `sse { }` overload
  registers a handler with **no HTTP-method selector**, so the SSE endpoint answered every verb.
  `OPTIONS / HTTP/1.1` with a rebound `Host:` and zero credentials therefore returned `200` plus
  `event: endpoint / data: ?sessionId=<uuid>` (reproduced against a running instance).

  Fixed by enforcing Host + Origin on **every** method and exempting only a *genuine* CORS preflight
  (`OPTIONS` **with** `Access-Control-Request-Method`) from the token check — a bare `OPTIONS` is now
  an ordinary request that needs a token — and by mounting every SSE route behind an explicit
  `method(HttpMethod.Get)` selector. Covered by 10 raw-socket regression tests
  (`SecurityInterceptorTest`).

  **No released version was exploitable**: on the shipped 2.2.x line the leaked session id was inert,
  because the back-channel still demanded the token. The session-id auth carrier that would have made
  it exploitable was introduced and removed within this release cycle, caught by an adversarial
  review before shipping. **A session id is deliberately not an authentication carrier**, so no
  future leak of one can become a token bypass.

## [2.2.2] — 2026-07-06

### Added
- MCP Activity: a **"Delete Saved History"** action that truly clears the durable log — the
  in-memory deque, this project's rows in the on-disk JSONL, and the dashboard event buffer — and a
  **"Persist activity"** toggle (`mcp_persist_activity`, default ON) with an always-visible
  `Saved: ON/OFF` status (issue #8). Enabling persistence flushes current in-memory activity to disk,
  not just future calls.

### Fixed
- The MCP Activity **"Clear"** button (now **"Clear View"**, cosmetic) no longer appears broken: it
  previously only emptied the table, so records reappeared on a filter change and after a Burp
  restart because the table re-renders from the deque and the saved file was never touched (issue #8).

## [2.2.1] — 2026-07-05

### Added
- `http_send_request` now returns an advisory **`warnings`** array when the method, URL, or a header
  value contains a raw CR/LF — the cause of Burp **"kettled"** HTTP/2 requests (issue #7). This lets
  an agent notice a stray newline (often emitted by the LLM) and self-correct. Advisory only — it
  never blocks, since sending CRLF on purpose (request-smuggling research) is a valid use.

## [2.2.0] — 2026-07-05 — Reliability, persistence & networking

Theme: reliability & persistence, plus the community-requested configurable bind host.

### Added
- **Configurable server bind host** (issue #4, contributed as PR #6 by **@Spark0618**, re-implemented
  hardened). The MCP + dashboard servers can bind to a chosen interface instead of loopback-only, for
  cross-machine / headless-Burp setups. Requested host resolves from `-Dburpmcp.bindHost`, else the
  `mcp_bind_host` preference, else `127.0.0.1`.
- **"Save & Rebind Now"** on the Server tab — hot-restarts the three servers on a new bind host
  **without an extension reload** (any live MCP client is briefly disconnected, as on a reload).
- **Durable dashboard activity** — MCP tool-call history now persists across extension reloads, Burp
  restarts, and crashes (project-tagged JSONL store), and repopulates both the native tab and the web
  dashboard on startup.

### Changed
- Bind-exposure / downgrade notices are logged to the **Output** tab with a `⚠ SECURITY` prefix
  (not the Errors tab) — they are warnings about a deliberate choice, not failures.
- Startup/log messages and all displayed connection URLs are now host-aware.

### Fixed
- **The 57-minute hang**: an SSE write to a client that stopped draining the stream could wedge the
  per-session write forever. Outbound SSE sends are now bounded by a timeout; on expiry the stalled
  session is torn down and the client reconnects (`TimeoutSseTransport` / `runWithSendTimeout`).
- **No-timeout hang class**: bounded the outbound HTTP sends in the probe/scan/import bridges.
- Restored MCP Activity rows are clickable again and counted in the live stats.
- A partial-init failure no longer orphans the listening sockets ("Address already in use" on the
  next reload): the unload handler is registered first and server start-up is wrapped so any failure
  stops the servers.

### Security
- A **non-loopback bind is gated**: it exposes Burp-driving tools and captured proxy history to the
  network behind only the bearer token, so it is honored **only** when the operator opts in
  (`mcp_allow_remote_bind` / `-Dburpmcp.allowRemoteBind`); otherwise the request is refused and
  downgraded to loopback. Exposure is warned loudly and written to the durable audit log. The
  Host-header + CORS allowlist extends to the configured host and this machine's own addresses only —
  never `anyHost()`. See `docs/SECURITY.md`.

## [2.1.1] — 2026-06-25

### Fixed
- MCP connection config corrected across every surface: the SSE endpoint is the **root path `/`**
  (not `/sse`) and a **bearer token is required**, single-sourced via `ConnectionInfo`.
- Systemic enum silent-failure bugs (B1–B7): closed-set parameters now fail loudly.
- `proxy_history_search` no longer silently returns zero for `search_in="url"`.

### Changed
- Version is single-sourced from the build (`BuildInfo.VERSION`) — no more hardcoded UI/dashboard drift.
- README accuracy pass (149 tools); LICENSE added.

## [2.1.0] — 2026-06-24

- Build compatibility (GitHub issues #2/#3): the fat JAR is pinned to JDK 17 bytecode so the MCP SSE
  ports bind reliably (a JAR built with Java 22+ silently failed to bind).
