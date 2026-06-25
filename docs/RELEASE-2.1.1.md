# Release 2.1.1 — execution checklist

Agreed scope from the pre-release audit (2 fresh-eyes agents + manual sweep). 2.1.1 stays
a **patch**: bug fixes + completing the issue-#1 endpoint fix, no new tools.

The already-committed 2.1.1 changes (version single-source, proxy_history_search url fix,
dashboard/banner version) were adversarially reviewed → **safe to ship, no blockers**.
This checklist is the *additional* gap-closure agreed before release.

## In 2.1.1

### A. Connection-config completion (issue-#1 fix was only applied to the README)
- [x] A1 — `DashboardServer.kt:437,438,441`: Connection-Info + Client-Config cards → root `/`; config card references the token (must NOT embed the real token in browser HTML)
- [x] A2 — `BurpMcpUltraTab.kt:845,846,857`: Server-tab labels + copy-paste config → root `/`
- [x] A3 — `configs/*.json` (×3): root `/` + `Authorization` header w/ token placeholder
- [x] A4 — `configs/setup.sh`: root `/` + token note
- [x] A5 — `McpServerManager.kt:30`: fix stale "GET /sse + POST /message" comment
- [x] F1 — single-source the connection config (one `ConnectionInfo` object for the in-app surfaces) so it can't drift again

### B. Silent-failure on unvalidated enum params (HIGH + MED)
- [x] B1 — `scancheck_register.location` (ScanCheckBridge): unknown → dead check. Error on unknown.
- [x] B2 — `scancheck_register.condition_type`: unknown → dead / false-positive-every-request. Error on unknown.
- [x] B3 — `proxy_set_request/response_rule.action`: unknown → inert rule reported as set. Validate {modify,drop,tag}.
- [x] B4 — `sitemap_get_issues.severity`: bad → filter disabled. Error on unparseable.
- [x] B5 — `collaborator_poll.type`: unknown → returns all. Error on unknown.
- [x] B6 — `scanner_create_issue.severity/confidence`: unknown → silent downgrade + masked echo. Validate/echo-actual.
- [x] B7 — `scanner_run_audit.audit_mode`: typo → silent ACTIVE scan. Error outside {light,normal,thorough}.

### C. Misc
- [x] C1 — add `LICENSE` (MIT, holder Cy-S3c) — referenced by README but missing
- [x] C2 — `docs/security-and-capability-review.md:4` "138 tools" → 149
- [x] D2 — `build.gradle.kts`: wire `compileTestKotlin dependsOn generateBuildInfo` explicitly

## Deferred to 2.1.2 (validation sweep)
- B8 LOW silent-failure items (direction, format, http_mode, bcheck, injection_probe classes echo, count=0 clamp)
- D1 systemic enum-validation framework (schema `enum` + shared resolve-or-error helper)
- C3 ProxyBridge empty-url over-match · D3 ReDoS guard on user regex (pre-existing)
- Full 149-tool live validation sweep

## Deferred to 2.2.0+
- CI (`.github/workflows`), CHANGELOG / CONTRIBUTING / SECURITY, social preview
