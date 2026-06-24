package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList

data class DeployedBCheck(
    val id: String,
    val name: String,
    val type: String,
    val script: String,
    val deployedAt: String
)

class BCheckBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager
) {
    private val deployedChecks = CopyOnWriteArrayList<DeployedBCheck>()

    /**
     * Generate a BCheck script from high-level parameters and import it.
     * This is the KEY method — the AI agent describes WHAT to check, this generates the HOW.
     */
    fun create(
        name: String,
        description: String,
        author: String?,
        tags: String?,
        type: String,  // passive_response, passive_request, insertion_point, host_level, path_level, collaborator
        // Match conditions (for passive checks)
        matchPattern: String?,      // Regex pattern to match
        matchLocation: String?,     // response_body, response_headers, request_body, request_headers, status_code
        matchCondition: String?,    // "matches" or "contains" or "is"
        // Active check params
        payloads: List<String>?,           // Payloads to inject (for insertion_point type)
        responseMatchPattern: String?,     // What to look for in the response after injection
        // Collaborator params
        collaboratorPayloadType: String?,  // dns, http
        // Issue reporting
        severity: String,           // high, medium, low, information
        confidence: String,         // certain, firm, tentative
        issueDetail: String?,
        issueRemediation: String?
    ): JsonObject {
        // Generate the BCheck script
        val script = generateScript(
            name, description, author ?: "BurpMCP-Ultra AI Agent", tags ?: "ai-generated",
            type, matchPattern, matchLocation, matchCondition,
            payloads, responseMatchPattern,
            collaboratorPayloadType,
            severity, confidence, issueDetail, issueRemediation
        )

        // Import into Burp
        return importScript(script, name, type)
    }

    /**
     * Import a raw BCheck script string directly.
     */
    fun importRaw(script: String): JsonObject {
        // Extract name from the script metadata
        val nameMatch = Regex("""name:\s*"([^"]+)"""").find(script)
        val name = nameMatch?.groupValues?.get(1) ?: "unnamed-bcheck"
        val typeGuess = when {
            script.contains("given insertion point") -> "insertion_point"
            script.contains("given host") -> "host_level"
            script.contains("given path") -> "path_level"
            script.contains("collaborator") -> "collaborator"
            script.contains("given response") -> "passive_response"
            script.contains("given request") -> "passive_request"
            else -> "unknown"
        }

        return importScript(script, name, typeGuess)
    }

    private fun importScript(script: String, name: String, type: String): JsonObject {
        return try {
            val result = api.scanner().bChecks().importBCheck(script)

            // Burp returns a status even when the script is syntactically parseable
            // but semantically invalid. Only treat LOADED_WITHOUT_ERRORS as success;
            // otherwise the BCheck is NOT active and must not be recorded as deployed.
            if (result.status() != burp.api.montoya.scanner.bchecks.BCheckImportResult.Status.LOADED_WITHOUT_ERRORS) {
                return buildJsonObject {
                    put("status", "error")
                    put("imported", false)
                    put("name", name)
                    put("type", type)
                    put("errors", buildJsonArray { result.importErrors().forEach { add(it) } })
                    put("script", script)
                    put("hint", "Check the BCheck syntax. Common issues: missing metadata, wrong scope keyword, invalid regex.")
                }
            }

            val id = stateManager.generateId("bcheck")
            deployedChecks.add(DeployedBCheck(
                id = id,
                name = name,
                type = type,
                script = script,
                deployedAt = Instant.now().toString()
            ))

            buildJsonObject {
                put("id", id)
                put("name", name)
                put("type", type)
                put("status", "deployed")
                put("deployed_at", Instant.now().toString())
                put("script", script)
                put("note", "BCheck is now active. It will run on all future scans and can also check existing proxy history.")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to import BCheck: ${e.message}")
                put("script", script)
                put("hint", "Check the BCheck syntax. Common issues: missing metadata, wrong scope keyword, invalid regex.")
            }
        }
    }

    /**
     * List all BChecks deployed via MCP.
     */
    fun list(): JsonObject {
        return buildJsonObject {
            put("count", deployedChecks.size)
            put("checks", buildJsonArray {
                deployedChecks.forEach { check ->
                    add(buildJsonObject {
                        put("id", check.id)
                        put("name", check.name)
                        put("type", check.type)
                        put("deployed_at", check.deployedAt)
                        put("script_preview", check.script.take(200))
                    })
                }
            })
        }
    }

    /**
     * Remove a deployed BCheck by ID.
     * Note: The Montoya API may not support removing individual BChecks.
     * We track removal in our state but Burp may need manual removal.
     */
    fun remove(id: String): JsonObject {
        val check = deployedChecks.find { it.id == id }
            ?: return buildJsonObject { put("error", "BCheck not found: $id") }

        deployedChecks.removeIf { it.id == id }

        return buildJsonObject {
            put("id", id)
            put("name", check.name)
            put("removed_from_tracking", true)
            put("note", "BCheck removed from MCP tracking. To fully remove from Burp, go to Extensions > Custom scan checks and delete '${check.name}'.")
        }
    }

    /**
     * Get BCheck script by ID (full script content).
     */
    fun getScript(id: String): JsonObject {
        val check = deployedChecks.find { it.id == id }
            ?: return buildJsonObject { put("error", "BCheck not found: $id") }

        return buildJsonObject {
            put("id", check.id)
            put("name", check.name)
            put("type", check.type)
            put("script", check.script)
        }
    }

    /**
     * Return all BCheck templates with descriptions and example code.
     * This teaches the AI agent the BCheck DSL patterns.
     */
    fun getTemplates(): JsonObject {
        return buildJsonObject {
            put("template_count", 7)
            put("bcheck_dsl_version", "v2-beta")
            put("templates", buildJsonArray {

                // Template 1: Passive Response Check
                add(buildJsonObject {
                    put("type", "passive_response")
                    put("name", "Response-level passive check")
                    put("description", "Matches patterns in HTTP responses. Runs on every response during passive scanning.")
                    put("use_cases", "Detect leaked API keys, exposed stack traces, sensitive data in responses, security header misconfigurations")
                    put("example", """
metadata:
    language: v2-beta
    name: "Leaked AWS Access Key"
    description: "Detects AWS Access Key IDs in HTTP responses"
    author: "BurpMCP-Ultra"
    tags: "aws", "secrets", "passive"

given response then
    if {latest.response.body} matches "AKIA[0-9A-Z]{16}" then
        report issue:
            severity: high
            confidence: firm
            detail: `AWS Access Key ID found in response body.`
            remediation: `Remove all hardcoded AWS credentials from application responses. Use environment variables or AWS Secrets Manager instead.`
    end if""".trimIndent())
                })

                // Template 2: Passive Request Check
                add(buildJsonObject {
                    put("type", "passive_request")
                    put("name", "Request-level passive check")
                    put("description", "Matches patterns in HTTP requests. Useful for detecting insecure client-side patterns.")
                    put("use_cases", "Detect credentials in URLs, insecure auth patterns, sensitive data in query strings")
                    put("example", """
metadata:
    language: v2-beta
    name: "Password in URL"
    description: "Detects passwords being sent in URL query parameters"
    author: "BurpMCP-Ultra"
    tags: "credentials", "passive"

given request then
    if {base.request.url} matches "(?i)(password|passwd|pwd|secret)=[^&]+" then
        report issue:
            severity: high
            confidence: certain
            detail: `Password or secret value detected in URL query parameters. This is logged in server access logs, browser history, and proxy logs.`
            remediation: `Send sensitive values in the request body (POST) instead of query parameters (GET). Use HTTPS for all authentication endpoints.`
    end if""".trimIndent())
                })

                // Template 3: Insertion Point (Active)
                add(buildJsonObject {
                    put("type", "insertion_point")
                    put("name", "Insertion-point-level active check")
                    put("description", "Injects payloads at each parameter and analyzes the response. The core of active scanning.")
                    put("use_cases", "Custom injection detection, input transformation detection, technology fingerprinting via error messages")
                    put("example", """
metadata:
    language: v2-beta
    name: "Server-side template injection (basic)"
    description: "Detects basic SSTI by injecting math expressions"
    author: "BurpMCP-Ultra"
    tags: "ssti", "injection", "active"

given insertion point then
    send payload called check_ssti:
        replacing: `${'$'}{7*7}`

    if {check_ssti.response.body} matches "49" then
        send payload called confirm_ssti:
            replacing: `${'$'}{7*6}`

        if {confirm_ssti.response.body} matches "42" then
            report issue:
                severity: high
                confidence: firm
                detail: `Server-side template injection detected. The expression ${'$'}{7*7} evaluated to 49 and ${'$'}{7*6} evaluated to 42, confirming server-side expression evaluation.`
                remediation: `Never pass user input directly into template engines. Use template engines in sandboxed mode. Validate and sanitize all user input before template processing.`
        end if
    end if""".trimIndent())
                })

                // Template 4: Host Level
                add(buildJsonObject {
                    put("type", "host_level")
                    put("name", "Host-level check")
                    put("description", "Runs once per unique host. Good for infrastructure checks.")
                    put("use_cases", "Exposed git directories, admin panels, backup files, directory listings, server version detection")
                    put("example", """
metadata:
    language: v2-beta
    name: "Exposed .git directory"
    description: "Checks if .git directory is publicly accessible"
    author: "BurpMCP-Ultra"
    tags: "git", "exposure", "host"

given host then
    send request called git_check:
        method: "GET"
        path: "/.git/config"

    if {git_check.response.status_code} is "200" and
        {git_check.response.body} matches "\[core\]" then
        report issue:
            severity: high
            confidence: certain
            detail: `The .git directory is publicly accessible. An attacker can download the entire source code repository, including commit history, branches, and potentially sensitive configuration files.`
            remediation: `Block access to .git directories in your web server configuration. For nginx: location ~ /\.git { deny all; }. For Apache: RedirectMatch 404 /\.git`
    end if""".trimIndent())
                })

                // Template 5: Path Level
                add(buildJsonObject {
                    put("type", "path_level")
                    put("name", "Path-level check")
                    put("description", "Runs once per unique path. Good for testing backup/alternate extensions.")
                    put("use_cases", "Backup file detection (.bak, .old, ~), alternate file extensions, source code exposure")
                    put("example", """
metadata:
    language: v2-beta
    name: "Backup file detection"
    description: "Checks for common backup file extensions"
    author: "BurpMCP-Ultra"
    tags: "backup", "exposure", "path"

define:
    extensions = ".bak", ".old", ".orig", ".save", ".swp", "~", ".tmp"

given path then
    run for each:
        extensions as ext

    send request called backup_check:
        method: "GET"
        path: `{base.request.url.path}{ext}`

    if {backup_check.response.status_code} is "200" then
        report issue:
            severity: medium
            confidence: tentative
            detail: `A backup file was found at {backup_check.request.url}. Backup files may contain source code, configuration details, or other sensitive information.`
            remediation: `Remove all backup files from production servers. Configure your deployment process to exclude backup files.`
    end if""".trimIndent())
                })

                // Template 6: Collaborator (OOB)
                add(buildJsonObject {
                    put("type", "collaborator")
                    put("name", "Request-level collaborator check")
                    put("description", "Uses Burp Collaborator for out-of-band (OOB) testing. Injects collaborator payloads and monitors for DNS/HTTP callbacks.")
                    put("use_cases", "Blind SSRF detection, blind XXE, blind command injection, DNS exfiltration")
                    put("example", """
metadata:
    language: v2-beta
    name: "Blind SSRF via Referer header"
    description: "Tests for blind SSRF by injecting a collaborator URL in the Referer header"
    author: "BurpMCP-Ultra"
    tags: "ssrf", "blind", "oob", "collaborator"

given request then
    send request called ssrf_test:
        method: `{base.request.method}`
        replacing header "Referer": `https://{generate_collaborator_address()}/ssrf-test`

    if dns interactions then
        report issue:
            severity: high
            confidence: firm
            detail: `Blind SSRF detected via Referer header. The server made a DNS lookup to the collaborator address injected in the Referer header, indicating it processes and follows URLs from this header.`
            remediation: `Validate and sanitize all URLs derived from user input. Implement allowlists for permitted external domains. Block outbound requests to internal network ranges.`
    end if""".trimIndent())
                })

                // Template 7: Multi-step with define block
                add(buildJsonObject {
                    put("type", "multi_step")
                    put("name", "Multi-step with variables")
                    put("description", "Complex check with multiple requests, variables, and conditional logic. Uses define blocks for reusable values and run-for-each for iteration.")
                    put("use_cases", "Complex vulnerability detection requiring multiple requests, IDOR verification, authentication bypass chains")
                    put("example", """
metadata:
    language: v2-beta
    name: "CORS misconfiguration"
    description: "Tests for permissive CORS configurations"
    author: "BurpMCP-Ultra"
    tags: "cors", "misconfiguration"

define:
    evil_origins = "https://evil.com", "null", "https://attacker.example.com"

given host then
    run for each:
        evil_origins as origin

    send request called cors_test:
        method: "GET"
        replacing header "Origin": `{origin}`

    if {cors_test.response.headers} matches "(?i)access-control-allow-origin:\s*((\*)|({origin}))" and
        {cors_test.response.headers} matches "(?i)access-control-allow-credentials:\s*true" then
        report issue:
            severity: high
            confidence: firm
            detail: `CORS misconfiguration detected. The server reflects the Origin header '{origin}' in Access-Control-Allow-Origin while also setting Access-Control-Allow-Credentials: true. This allows an attacker-controlled domain to read authenticated responses cross-origin.`
            remediation: `Implement a strict allowlist of permitted origins. Never reflect arbitrary Origin values when Access-Control-Allow-Credentials is true. Never use Access-Control-Allow-Origin: * with credentials.`
    end if""".trimIndent())
                })
            })

            put("dsl_reference", buildJsonObject {
                put("metadata_fields", buildJsonArray {
                    add("language: v2-beta (required)")
                    add("name: \"Check name\" (required)")
                    add("description: \"What it does\" (required)")
                    add("author: \"Author name\"")
                    add("tags: \"tag1\", \"tag2\"")
                })
                put("scope_keywords", buildJsonArray {
                    add("given response then - passive, runs on every response")
                    add("given request then - passive, runs on every request")
                    add("given insertion point then - active, runs at each insertion point")
                    add("given host then - once per unique host")
                    add("given path then - once per unique path")
                })
                put("request_operations", buildJsonArray {
                    add("send request called <name>: method: \"GET\" path: \"/test\"")
                    add("send payload called <name>: replacing: `payload_value`")
                    add("replacing header \"Name\": `value` - modify a header")
                })
                put("conditions", buildJsonArray {
                    add("{var.response.body} matches \"regex\"")
                    add("{var.response.status_code} is \"200\"")
                    add("{var.response.headers} matches \"regex\"")
                    add("dns interactions - collaborator DNS callback detected")
                    add("http interactions - collaborator HTTP callback detected")
                    add("not(...) - negate a condition")
                    add("... and ... - combine conditions")
                    add("... or ... - alternative conditions")
                })
                put("variables", buildJsonArray {
                    add("{base.request.url} - original request URL")
                    add("{base.request.url.path} - original request path")
                    add("{base.request.method} - original request method")
                    add("{base.request.body} - original request body")
                    add("{latest.response.body} - most recent response body")
                    add("{latest.response.status_code} - most recent status code")
                    add("{latest.response.headers} - most recent response headers")
                    add("{generate_collaborator_address()} - generate OOB payload")
                })
                put("reporting", buildJsonArray {
                    add("severity: high | medium | low | information")
                    add("confidence: certain | firm | tentative")
                    add("detail: `Issue description with {variables}`")
                    add("remediation: `How to fix`")
                })
            })
        }
    }

    /**
     * Generate a BCheck script from structured parameters.
     */
    private fun generateScript(
        name: String,
        description: String,
        author: String,
        tags: String,
        type: String,
        matchPattern: String?,
        matchLocation: String?,
        matchCondition: String?,
        payloads: List<String>?,
        responseMatchPattern: String?,
        collaboratorPayloadType: String?,
        severity: String,
        confidence: String,
        issueDetail: String?,
        issueRemediation: String?
    ): String {
        val sb = StringBuilder()

        // Metadata
        sb.appendLine("metadata:")
        sb.appendLine("    language: v2-beta")
        sb.appendLine("    name: \"$name\"")
        sb.appendLine("    description: \"$description\"")
        sb.appendLine("    author: \"$author\"")
        sb.appendLine("    tags: ${tags.split(",").joinToString(", ") { "\"${it.trim()}\"" }}")
        sb.appendLine()

        val detail = issueDetail ?: "$name was detected."
        val remediation = issueRemediation ?: "Review and fix the identified issue."

        when (type.lowercase()) {
            "passive_response" -> {
                sb.appendLine("given response then")
                val location = when (matchLocation?.lowercase()) {
                    "response_headers", "headers" -> "{latest.response.headers}"
                    "status_code" -> "{latest.response.status_code}"
                    else -> "{latest.response.body}"
                }
                val condition = matchCondition ?: "matches"
                sb.appendLine("    if $location $condition \"${escapeRegex(matchPattern ?: "")}\" then")
                sb.appendLine("        report issue:")
                sb.appendLine("            severity: $severity")
                sb.appendLine("            confidence: $confidence")
                sb.appendLine("            detail: `$detail`")
                sb.appendLine("            remediation: `$remediation`")
                sb.appendLine("    end if")
            }

            "passive_request" -> {
                sb.appendLine("given request then")
                val location = when (matchLocation?.lowercase()) {
                    "request_headers", "headers" -> "{base.request.headers}"
                    "request_body", "body" -> "{base.request.body}"
                    else -> "{base.request.url}"
                }
                val condition = matchCondition ?: "matches"
                sb.appendLine("    if $location $condition \"${escapeRegex(matchPattern ?: "")}\" then")
                sb.appendLine("        report issue:")
                sb.appendLine("            severity: $severity")
                sb.appendLine("            confidence: $confidence")
                sb.appendLine("            detail: `$detail`")
                sb.appendLine("            remediation: `$remediation`")
                sb.appendLine("    end if")
            }

            "insertion_point" -> {
                if (payloads != null && payloads.isNotEmpty()) {
                    sb.appendLine("define:")
                    sb.appendLine("    test_payloads = ${payloads.joinToString(", ") { "\"$it\"" }}")
                    sb.appendLine()
                    sb.appendLine("given insertion point then")
                    sb.appendLine("    run for each:")
                    sb.appendLine("        test_payloads as payload")
                    sb.appendLine()
                    sb.appendLine("    send payload called inject_test:")
                    sb.appendLine("        replacing: `{payload}`")
                    sb.appendLine()
                    val respMatch = responseMatchPattern ?: matchPattern ?: ""
                    sb.appendLine("    if {inject_test.response.body} matches \"${escapeRegex(respMatch)}\" then")
                    sb.appendLine("        report issue:")
                    sb.appendLine("            severity: $severity")
                    sb.appendLine("            confidence: $confidence")
                    sb.appendLine("            detail: `$detail Payload: {payload}`")
                    sb.appendLine("            remediation: `$remediation`")
                    sb.appendLine("    end if")
                } else {
                    // Single payload from matchPattern
                    sb.appendLine("given insertion point then")
                    sb.appendLine("    send payload called inject_test:")
                    sb.appendLine("        replacing: `${matchPattern ?: "FUZZ"}`")
                    sb.appendLine()
                    val respMatch = responseMatchPattern ?: "error|exception|stack.trace"
                    sb.appendLine("    if {inject_test.response.body} matches \"${escapeRegex(respMatch)}\" then")
                    sb.appendLine("        report issue:")
                    sb.appendLine("            severity: $severity")
                    sb.appendLine("            confidence: $confidence")
                    sb.appendLine("            detail: `$detail`")
                    sb.appendLine("            remediation: `$remediation`")
                    sb.appendLine("    end if")
                }
            }

            "host_level" -> {
                sb.appendLine("given host then")
                sb.appendLine("    send request called host_check:")
                sb.appendLine("        method: \"GET\"")
                sb.appendLine("        path: \"${matchPattern ?: "/"}\"")
                sb.appendLine()
                val respMatch = responseMatchPattern ?: matchPattern ?: ""
                val condition = matchCondition ?: "matches"
                sb.appendLine("    if {host_check.response.status_code} is \"200\" and")
                sb.appendLine("        {host_check.response.body} $condition \"${escapeRegex(respMatch)}\" then")
                sb.appendLine("        report issue:")
                sb.appendLine("            severity: $severity")
                sb.appendLine("            confidence: $confidence")
                sb.appendLine("            detail: `$detail`")
                sb.appendLine("            remediation: `$remediation`")
                sb.appendLine("    end if")
            }

            "path_level" -> {
                val extensions = payloads ?: listOf(".bak", ".old", ".orig", ".swp", "~")
                sb.appendLine("define:")
                sb.appendLine("    test_extensions = ${extensions.joinToString(", ") { "\"$it\"" }}")
                sb.appendLine()
                sb.appendLine("given path then")
                sb.appendLine("    run for each:")
                sb.appendLine("        test_extensions as ext")
                sb.appendLine()
                sb.appendLine("    send request called path_check:")
                sb.appendLine("        method: \"GET\"")
                sb.appendLine("        path: `{base.request.url.path}{ext}`")
                sb.appendLine()
                sb.appendLine("    if {path_check.response.status_code} is \"200\" then")
                sb.appendLine("        report issue:")
                sb.appendLine("            severity: $severity")
                sb.appendLine("            confidence: $confidence")
                sb.appendLine("            detail: `$detail Found at: {path_check.request.url}`")
                sb.appendLine("            remediation: `$remediation`")
                sb.appendLine("    end if")
            }

            "collaborator" -> {
                sb.appendLine("given request then")
                val headerName = matchLocation ?: "Referer"
                sb.appendLine("    send request called collab_test:")
                sb.appendLine("        method: `{base.request.method}`")
                sb.appendLine("        replacing header \"$headerName\": `${matchPattern ?: "https://{generate_collaborator_address()}"}`")
                sb.appendLine()
                val interactionType = collaboratorPayloadType ?: "dns"
                sb.appendLine("    if $interactionType interactions then")
                sb.appendLine("        report issue:")
                sb.appendLine("            severity: $severity")
                sb.appendLine("            confidence: $confidence")
                sb.appendLine("            detail: `$detail`")
                sb.appendLine("            remediation: `$remediation`")
                sb.appendLine("    end if")
            }

            else -> {
                // Default to passive response
                sb.appendLine("given response then")
                sb.appendLine("    if {latest.response.body} matches \"${escapeRegex(matchPattern ?: "")}\" then")
                sb.appendLine("        report issue:")
                sb.appendLine("            severity: $severity")
                sb.appendLine("            confidence: $confidence")
                sb.appendLine("            detail: `$detail`")
                sb.appendLine("            remediation: `$remediation`")
                sb.appendLine("    end if")
            }
        }

        return sb.toString()
    }

    private fun escapeRegex(pattern: String): String {
        // BCheck uses its own regex dialect - don't double-escape
        return pattern.replace("\"", "\\\"")
    }

    fun getDeployedChecks(): List<DeployedBCheck> = deployedChecks.toList()
}
