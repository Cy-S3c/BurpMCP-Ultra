# BurpMCP-Ultra — Security, Correctness & Capability Review

> Author: project audit, 2026-06-12. Lenses: security researcher, pentester, security engineer, red-teamer, web hacker.
> Scope: full project (~19.6k LOC, 24 bridges → 138 MCP tools + 8 resources, 3 localhost servers).
> Evidence cites `file:line`. Claims marked *(verify)* are high-confidence from a sub-analysis but not independently line-confirmed.

---

## 0. What the project is (inventory)

An MCP server embedded in a Burp Suite Pro extension. It lets an LLM agent drive Burp:

- **Transport**: `McpServerManager` runs two SSE MCP servers (9876 primary, 9877 secondary/duplicate) + `DashboardServer` web UI on 9878. All bind `127.0.0.1`. `SecurityConfig.installLocalhostSecurity` adds a Host-header allowlist (anti-DNS-rebind), Origin lockdown, and a per-install 256-bit bearer token (constant-time compare). Token persisted in Burp prefs (stable).
- **Bridges (24)**: thin Montoya wrappers — HTTP, Proxy, Scanner, Collaborator, Intruder, WebSocket, Scope, Sitemap, Session, Config, BCheck, ScanCheck, Analysis, PassiveIntel, ApiImport, AI, Utilities, etc.
- **Tools (138)** across 30 domains: send/chain/parallel/race/fuzz HTTP, proxy history + live traffic rules, scanner audit/crawl + custom checks, collaborator OOB, intruder, websocket, auth-diff, passive secret scan, OpenAPI import, JWT/encoding utils, structured analysis.
- **State**: `StateManager` (rules, ws connections, scan tasks, collaborator clients, MCP activity ring). `EventBus` (bounded 10k, push + cursor poll).

**Verdict:** an excellent **HTTP execution engine** with a clean bridge/tool architecture and a genuinely well-thought-out loopback security model — but it is a weak **hunter** (no recon, no guided detection, no memory), it has **no safety governance** over a powerful autonomous agent, and it carries several **correctness bugs and one no-op security feature**.

---

## 1. Security hardening of the tool itself (HIGHEST PRIORITY)

This tool hands an LLM the ability to send arbitrary requests anywhere, rewrite live traffic, and shut down Burp. The trust boundary is strong at the network layer but absent at the authorization layer.

| Sev | Issue | Evidence | Fix |
|---|---|---|---|
| **Crit** | **No scope enforcement on any outbound request.** Agent can hit *any* host (SSRF / pivot via operator's network), ignoring Burp target scope. | `HttpBridge` builds `HttpService` from caller host/port; `isInScope` appears only in `ScopeBridge.kt:12` (a query), never in the send path | Add an operator-configured policy gate in `HttpBridge` before every send/sendRawBytes/parallel/chain: deny out-of-scope unless an **operator** (not agent) flag allows it. |
| **Crit** | **Destructive tools fully agent-controlled.** `burp_shutdown` `prompt_user` defaults `false` (`BurpSuiteTools.kt:253`); `burp_import_project_config`/`import_user_config` have no gate. Prompt-injected content the agent reads can trigger these. | `BurpSuiteTools.kt:246,253`; import tools | Server-side allowlist/confirmation in `ToolCallTracker` (it already wraps every call): destructive tools require a human-approved nonce or are dry-run by default. Confirmation must NOT be a tool argument. |
| **Crit** | **Token confidentiality.** Token is logged to Burp output in two forms (`BurpMcpUltraExtension.kt:88,92`) and the dashboard passes it as a **URL query param** *(verify: `DashboardServer.kt` ~1008-1100)* → browser history, Referer, access logs. | as cited | Show token only in the Swing tab (copy field). Authenticate the dashboard with an `HttpOnly; SameSite=Strict` cookie set when `/` is served — not `?token=`. |
| **High** | **No rate limiting / connection caps** on any of the 3 servers; SSE holds a coroutine per subscriber. | no throttle/semaphore in transport *(verify)* | Per-IP request rate limit + max SSE connections. |
| **High** | **Audit log is cosmetic.** `ToolCallTracker` emits to UI/dashboard only, truncates args to 200 chars, swallows exceptions — nothing durable for forensics after restart. | `ToolCallTracker.kt` | Append-only file log (untruncated) for destructive/outbound tools: caller, ts, args, result. Don't swallow. |
| **Med** | Full **config export** resources (`config/project`, `config/user`) are token-gated but unredacted — may leak upstream-proxy creds / API keys. | `ResourceRegistry.kt:163,177` | Redact secrets or move behind the destructive gate. |
| **Med** | **JSON built by string concatenation** in the dashboard (only `"`→`'`), so exception text can break/inject fields. | `DashboardServer.kt:112` *(verify)* | Use `kotlinx.serialization`. |
| **Low** | **Redundant 9877 listener** doubles attack surface for identical functionality. | `McpServerManager.kt:45-46` | Drop unless it serves a distinct purpose. |

---

## 2. Correctness bugs & wrongly-developed / misplaced code

### Correctness / robustness (with fixes)
| Sev | Issue | Evidence | Fix |
|---|---|---|---|
| **Crit** | **Session rules never applied** — stored + shown in UI but no enforcement path; `sessionRules` is read only for a count. A *false security control*. | `sessionRules` used only at `ExtensionBridge.kt:61`; `HttpBridge` global handler processes only `trafficRules` | Implement extract→inject in `createGlobalHttpHandler`, or remove the feature + its docstring claims. |
| **Crit** | **Regex DoS on Burp threads** — every proxy/traffic/session rule does `Regex(...)` **per request**, no timeout; catastrophic-backtracking pattern hangs the pipeline. | `ProxyBridge.kt:520-664`, `HttpBridge.kt:601-638` *(verify line set)* | Pre-compile `Pattern` at rule creation; bound input length; watchdog. |
| **High** | **CRLF / header injection** — `modifyAddHeader` split on `:` then `withAddedHeader` with no `\r\n` check → request injection into live traffic. | `ProxyBridge.kt:601-648`, `HttpBridge.kt:652-686` *(verify)* | Reject CR/LF in header name/value. |
| **High** | **Unbounded history/body copies** — `count`/`maxResults` accept arbitrary ints, `includeResponse` copies full bodies → OOM. | `ProxyBridge.kt:114-187`, `ProxyTools.kt:49,108` *(verify)* | Clamp to hard max; default-truncate bodies. |
| **High** | **Unbounded WebSocket message buffer** — `connection.messages` is a `CopyOnWriteArrayList` (every append copies the whole array → O(n²) + no eviction). | `StateManager.kt:129` (confirmed) | Bounded ring buffer with eviction; not COW for an append log. |
| **High** | **Blocking `sendRequest` loop on a scanner thread** in active audit, no per-payload timeout. | `ScannerBridge.kt:713-748` *(verify)* | Cap payloads; timeout-wrap sends. |
| **Med** | **Content-Length charset mismatch** — body sized as ISO-8859-1 but transmitted UTF-8 → wrong CL for multi-byte bodies (reintroduces the status_code:0 ghost). | `HttpBridge.kt:872-900` *(verify)* | Size in the same charset Burp sends (UTF-8) or stay in raw bytes. |
| **Med** | `urlEncode` `encodeAll=true` is a **silent no-op** (both branches identical). | `UtilitiesBridge.kt:24-30` *(verify)* | Implement or drop the param. |
| **Med** | Broad `catch(_)` in `serializeRequestResponse` silently drops the whole response block on any field error. | `HttpBridge.kt:1357-1395` *(verify)* | Narrow catch; emit `serialize_error`. |

### Wrongly developed / misplaced — and the correct placement
1. **Montoya API via reflection.** `AnalysisTools.kt:322` & `AuthDiffTools.kt:62` do `bridges.burpSuite.javaClass.getDeclaredField("api"); isAccessible=true`. **Correct:** add `api` (or an `AnalysisBridge`) to `BridgeFactory.Bridges` and inject it normally. Fragile reflection that breaks on obfuscation/refactor.
2. **`startAudit` writes a persistent global traffic rule to inject an auth header** *(verify: `ScannerBridge.kt:110-123`)* — cross-cutting state that affects *all* traffic, not just the audit. **Correct:** scope the auth to the task and auto-remove on `deleteTask`, via a session/auth abstraction.
3. **Duplicated header/rule logic** verbatim across `HttpBridge` and `ProxyBridge` (colon-split, `withAddedHeader`, match helpers). **Correct:** extract a shared `HeaderRuleApplier` + `RuleMatcher` (also the single place to add CRLF validation and precompiled regex).
4. **`analyze_variations` lives in HttpTools, not Analysis** — minor domain misplacement; move for discoverability.
5. **Confirmation-as-tool-argument** (`prompt_user`) is governance in the wrong layer — see §1.

---

## 3. Offensive capability gaps — what to ADD (pentester/red-team/web-hacker)

**Coverage scorecard:** Strong — raw HTTP/smuggling primitives, scanner integration, collaborator OOB, websocket, encoding, passive intel. Partial — race (`http_race` is best-effort, not single-packet), fuzzing (sniper-only), auth-diff (single request), reflection triage. **Missing** — recon/content discovery, param mining, JS endpoint extraction, GraphQL, JWT *attacks*, OAuth/SAML, CORS/cache-poisoning probes, structured findings memory.

**Top additions (prioritized):**

| # | Add | Why | Where | Effort |
|---|---|---|---|---|
| 1 | **`util_jwt_attack`** — alg=none, RS256→HS256 confusion, `kid` path/SQLi injection, jku/x5u swap, weak-secret crack | JWT is the #1 auth bug class; current tool only decodes/verifies | new `JwtBridge` | M |
| 2 | **`recon_content_discovery`** — wordlist dir/file brute on the parallel engine with 404 baselining | No discovery = agent only tests what it's handed | new `ReconBridge` | M |
| 3 | **`recon_param_mine`** — Arjun-style hidden-param discovery (reflection/behavioral) | Hidden params hide IDOR/XSS/SSRF | recon/http | M |
| 4 | **`recon_js_endpoints`** — extract endpoints/secrets/routes from JS in history | SPAs expose the API surface in JS | recon/analysis | S |
| 5 | **`graphql_probe`** — introspection, field suggestion when disabled, batching/alias abuse | Ubiquitous, zero coverage today | new `GraphQLBridge` | M |
| 6 | **`access_control_sweep`** — replay sitemap/N requests across an identity set, flag identical/2xx cross-user | Scales IDOR/BOLA beyond single-request `auth_diff` | extend authdiff | M |
| 7 | **`injection_probe`** — guided SQLi/SSTI/cmdi/traversal/SSRF with detection oracles (error sigs, time-delay, collaborator OOB, math-eval) | Turns raw fuzz into confirmed findings; wires OOB into blind chains | new `InjectionBridge` | L |
| 8 | **`http_smuggle_probe`** — CL.TE/TE.CL/H2.CL/CL.0 differential templates + timing oracle atop `send_raw_bytes` | Primitive exists, attacks must be hand-built | http | M |
| 9 | **`findings_store`** — structured add/list/dedup(by rule+location)/retest schema | LLM has no memory of confirmed bugs; enables triage/dedup/regression | new `FindingsBridge`/state | M |
| 10 | **`race_singlepacket`** — true H2 single-packet / H1 last-byte sync | `http_race` can't do the attacks that actually win limit-overrun bugs | http | L |
| 11 | **`cors_probe` + `cache_probe`** — reflect/null origin; unkeyed-header / web-cache-deception oracle | Quick high-severity wins, absent | new misc-web bridge | S |
| 12 | **`recon_fingerprint`** — tech/WAF/framework fingerprint from headers/favicon/body | Drives payload selection (SSTI engine, WAF bypass) downstream | recon/passive | S |

---

## 4. Feature-depth improvements (make existing "smart" tools real)

- **API import (highest ROI):** add `$ref` resolution against `components/schemas`/`definitions` before body generation — without it every imported POST body is `{}` *(ApiImportBridge.kt:266-297, verify)*. Honor `enum/required/format`, OAS3 `parameter.content`, multiple `servers`, `securitySchemes` (auto-auth). Accept YAML.
- **Auth diff → real IDOR mode:** same token, swap object-ID across two user contexts; add a control/baseline request; flag `unauth==auth` for any 2xx/3xx (not just 200); make stripped headers configurable (don't blindly drop `Cookie` for header-auth).
- **JWT decode → surface offensive findings:** return a `security_issues[]` (alg:none, key confusion, missing exp, kid/jku/x5u injection points, weak-HMAC hint).
- **Passive intel:** Shannon-entropy gate for high-FP patterns (UUID/heroku/bearer), exact-match category filter, JS/`.map` fetching, verified-secret tiers; feed hits into `findings_store`.
- **ScanCheck:** persist regex capture groups from step N → N+1 (enables real chained exploits); add `case_sensitive` flag; restrict to chosen insertion-point types.
- **Intruder:** add results retrieval (consume `AttackResult`) — today it's fire-and-forget into the UI.
- **`http_fuzz`:** cluster-bomb/pitchfork modes, built-in named payload libraries (xss/sqli/traversal/ssti), auto-anomaly flagging via the existing `analyze_variations` engine.
- **Insertion points:** emit JSON/XML body leaf nodes (parity with `extractParams`) + byte offsets that feed `intruder_send_with_positions` directly.

---

## 5. Prioritized roadmap (exhaustive — every finding scheduled)

Each item carries its finding ID from §1–§4 so coverage is traceable. IDs:
S1-S8 (§1 security), C1-C9 (§2 correctness), M1-M5 (§2 misplaced), N1-N12 (§3 new), D1-D8 (§4 depth).

> **Progress (2026-06-15) — shipped & verified (build green, 50 unit tests). All four review areas now have landed work:**
> - ① ✅ **S1** scope gate, **C2** ReDoS-safe regex, **C3** CRLF validation, **M3** shared rule helpers — `b3f8d94`
> - ② ✅ **C1** session rules now actually applied (was a no-op) — `9376b97`
> - ② ✅ **M1** AnalysisBridge first-class (reflection removed), **C8** urlEncode encodeAll — `1633ad8`
> - ③ ✅ **N1** `jwt_attack` tool (alg:none, RS→HS confusion, secret crack, analysis) — `1e43d1a`
> - ④ ✅ **D1** API-import `$ref`/allOf/enum resolution (imported bodies are real now) — `2df0819`
> - ① ✅ **S2** destructive-tool gate (`mcp_allow_destructive`), **S3a** token not logged — `af61607`
> - ① ✅ **S3b** dashboard cookie auth (token out of URLs) `46ab659` · **C4/C5** history + WS-buffer caps `cfde07f` · **S5** durable audit log `bc395f3` → **① SECURITY TIER COMPLETE**
> - ④ ✅ **D4** passive-intel entropy de-noising `6381de4` · **D2** auth-diff broken-access-control verdict `70c5cb8`
> - ③ ✅ **N9** findings store `1232226` · **N2/N3/N4** recon trio — JS endpoints, content discovery, param mining `42f5f48`
> - ③ ✅ **N5** `graphql_probe` `ac16e71` · **N11** `cors_probe` + **N12** `recon_fingerprint` `7715f16`
> - ② ✅ **C9** serialize-error surfacing `a3166d8`
> - 🛡️ **Adversarial self-review** (workflow: 5 dimensions + per-finding verification) found **7 real bugs in this session's own code** — all fixed in `449eb96`: [HIGH] scope-gate bypass via http_send_parallel/chain/fuzz/race (now all 6 paths gate through a centralized `ScopeGate`); [MED] chain-extract ReDoS (raw regex → SafeRegex); [MED] Jwt.crack empty-key crash; [MED] session cookie/body CRLF; [LOW] WARN-flag gaps in recon/graphql/webprobe; [LOW] per-path content-discovery scope; [LOW] hot-path body materialization.
> - ④ ✅ **D8** JSON-body insertion points `35e9b35` · **D7** payload libraries for http_fuzz `ffdf526` · ③ ✅ **N6** access_control_sweep + scope-gated auth_diff `10ae737`
> - ❌ **D6** intruder-results retrieval is INFEASIBLE — Montoya's Intruder API is fire-and-forget (sendToIntruder + register processors only; no result readback). Use http_fuzz for programmatic fuzzing results.
> - ⏳ Remaining: ② C6 (scanner loop), C7 (charset — runtime-verify), M2, M4, S7 · ③ N7 injection-oracle, N8 smuggling, N10 single-packet race · ④ D5 ScanCheck-chaining, D7 cluster-bomb mode · P3.
> (Session: 101 unit tests, build green, 149 tools.)

**P0 — safety & correctness (do first; small, high-impact, verified):**
1. Scope gate on all outbound HTTP (operator-controlled). — **S1**
2. Implement OR remove session rules (no-op security control). — **C1**
3. Pre-compile + bound rule regexes **and** CRLF-validate header writes, via a shared `RuleMatcher` + `HeaderRuleApplier`. — **C2, C3, M3**
4. Stop logging the token / stop query-string token; UI-only display + cookie auth. — **S3**
5. Server-side gate for destructive tools (shutdown, import config); remove `prompt_user` as the control. — **S2, M5**
6. Clamp history/result sizes; default-truncate bodies; bound WS message buffer. — **C4, C5**

**P0.5 — cheap correctness & cleanup (bundle into the P0 PRs):**
7. Bound scanner active-audit payload loop + per-payload timeout. — **C6**
8. Fix Content-Length charset mismatch (size in UTF-8 / raw bytes). — **C7**
9. Fix or remove `urlEncode` `encodeAll` no-op. — **C8**
10. Narrow broad `catch(_)` in `serializeRequestResponse`; emit `serialize_error`. — **C9**
11. Remove reflection hack — expose `api`/`AnalysisBridge` on `BridgeFactory.Bridges`. — **M1**
12. `startAudit`: scope the injected auth header to the task, auto-remove on delete — not a global traffic rule. — **M2**
13. Dashboard responses via `kotlinx.serialization`, not string concat. — **S7**
14. Move `analyze_variations` from HttpTools to the Analysis domain. — **M4**

**P1 — capability & depth:**
15. API import: `$ref` resolution + `securitySchemes` auto-auth + YAML. — **D1**
16. `findings_store` (structured agent memory + dedup + retest). — **N9**
17. JWT attack tool (alg:none, RS→HS confusion, kid/jku injection, secret crack) + decode `security_issues[]`. — **N1, D3**
18. auth_diff → real cross-identity IDOR mode + control baseline. — **D2**
19. Recon trio: content discovery, param mining, JS-endpoint extraction. — **N2, N3, N4**
20. `recon_fingerprint` (tech/WAF/framework). — **N12**
21. Passive intel: Shannon-entropy gating, JS/source-map scraping, verified-secret tiers, exact-match category filter. — **D4**
22. ScanCheck: persist regex capture groups across steps + `case_sensitive` flag + insertion-point filtering. — **D5**
23. Intruder: results retrieval (consume `AttackResult`). — **D6**
24. `http_fuzz`: cluster-bomb/pitchfork, built-in payload libraries, auto-anomaly via `analyze_variations`. — **D7**
25. Insertion points: emit JSON/XML leaf nodes + byte offsets feeding `intruder_send_with_positions`. — **D8**
26. Durable append-only audit log + rate limiting + SSE connection caps. — **S5, S4**

**P2 — new high-value attack surfaces:**
27. GraphQL probe (introspection, field suggestion, batching/alias abuse). — **N5**
28. Injection oracle (guided SQLi/SSTI/cmdi/traversal/SSRF + collaborator OOB). — **N7**
29. `http_smuggle_probe` (CL.TE/TE.CL/H2.CL/CL.0 + timing oracle). — **N8**
30. `race_singlepacket` (true H2 single-packet / H1 last-byte sync). — **N10**
31. `cors_probe` + `cache_probe` (reflect/null origin; unkeyed-header / web-cache deception). — **N11**
32. `access_control_sweep` across the sitemap (privilege matrix). — **N6**

**P3 — residual hardening (low):**
33. Redact secrets from `config/project` + `config/user` resource exports. — **S6**
34. Drop the redundant 9877 SSE listener (or justify it). — **S8**
35. Token rotation (UI button to regenerate `mcp_auth_token`).

**Coverage:** every finding S1–S8, C1–C9, M1–M5, N1–N12, D1–D8 maps to exactly one roadmap item above (D3 folds into 17). Nothing is left unscheduled.

**Strengths to preserve:** clean bridge/tool separation; the Host+Origin+token loopback model; genuine ScanCheck/BCheck implementations; the raw-byte HTTP engine; the now-correct collaborator integration.
