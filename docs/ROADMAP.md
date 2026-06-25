# BurpMCP-Ultra — Roadmap

Living planning doc. Groups all known/outstanding work into semver buckets.
Source inputs: `docs/security-and-capability-review.md` (the original audit roadmap),
items discovered during live validation, and project-maturity gaps.

**Semver convention used here**
- **patch (2.1.x)** — bug fixes, robustness, docs. No new tools, no breaking changes.
- **minor (2.x.0)** — new tools / capabilities, backward compatible.
- **major (3.0.0)** — breaking changes (dropping a port, renaming/removing tools, changing the execution model or transport).

---

## Master list (everything on the table, by theme)

### 1. Validation & correctness  *(highest-value)*
- Only ~8 of 149 tools have been exercised against a live Burp. The first 8 already
  surfaced one real bug (`proxy_history_search` silent-zero). A systematic live sweep
  of every tool category will surface more.
- **C6** — scanner-loop bound (correctness).
- **C7** — Content-Length charset (now runtime-verifiable; Burp encodes raw requests).
- **S7** — dashboard JSON serialization.
- `recon_js_endpoints` UX — raise default `max_items` or warn on a small scan window.

### 2. Security hardening (P3)
- **S6** — config-export redaction (don't leak secrets in exported config).
- **Token rotation**.
- **S8** — drop / justify the redundant secondary SSE port 9877.
- **Active-tool throttle / rate-limit** — stop an agent hammering a live target.

### 3. New offensive capabilities
- **N8** — HTTP request smuggling (large, runtime-dependent).
- **N10** — single-packet / HTTP-2 race (large, runtime-dependent).
- Findings **export & reporting** (SARIF / Markdown).
- WebSocket fuzzing depth; nuclei-style templating (ideas).

### 4. Tool depth / quality
- **D5** — ScanCheck capture-group chaining.
- **D7** — cluster-bomb multi-position fuzz mode.
- **M2 / M4** — relocate misplaced tools (renaming a tool is breaking → alias then remove).

### 5. Performance & architecture
- Slow tools (`passive_intel` / recon over ~2000 items) take 60–90s and block the MCP
  POST — investigate async / concurrent tool execution.
- Streaming / pagination for heavy scanners.

### 6. CI/CD & engineering
- **GitHub Actions** — JDK-17 build + tests on every push (would have caught the build
  issues automatically).
- More unit coverage for the new tools.
- Single-source the **tool count** (drifted 150/149) like the version now is.

### 7. Docs & community
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, social-preview image,
  GitHub Discussions, regenerated tool catalog.

### 8. Collaborator
- Native-tab access documented infeasible; Collaborator UX / correlation could improve.

---

## Version structure

| Version | Type | Theme | Contents |
|---|---|---|---|
| **2.1.1** | patch | *(parked, built & live-verified)* | proxy_history_search url fix; single-sourced version; dashboard/banner version fixes |
| **2.1.2** | patch | Validation sweep | live-test all 149 tools in batches; fix what breaks + C6, C7, S7 |
| **2.1.3** | patch | Security P3 | S6 redaction, token rotation, active-tool throttle |
| **2.2.0** | minor | DX & depth | CI (Actions), CHANGELOG/CONTRIBUTING/SECURITY, D5, D7, tool-count single-source, more tests |
| **2.3.0** | minor | Smuggling | N8 HTTP request smuggling |
| **2.4.0** | minor | Race | N10 single-packet / HTTP-2 race |
| **2.5.0** | minor | Reporting | findings export (SARIF / Markdown), Collaborator UX |
| **3.0.0** | major | Architecture | async/concurrent tool execution, drop port 9877, Streamable-HTTP transport, M2/M4 tool renames (remove old aliases) |

---

## Guiding principle

**Validate before building.** The 2.1.2 sweep is the highest-value next step: the
live-validation pattern already caught a real silent-data-loss bug in the first handful
of tools. Confirm the 149-tool base is solid before stacking new tooling, CI, and docs
on top of it.

## Open questions
1. Validate-first (2.1.2) vs. push new offensive tooling (N8/N10) sooner?
2. Treat tool renames (M2/M4) and dropping port 9877 as 3.0 breaking changes, or stay
   additive and avoid a major bump?
