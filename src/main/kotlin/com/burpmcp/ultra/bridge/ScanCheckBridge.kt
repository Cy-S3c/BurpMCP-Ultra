package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.core.ByteArray as BurpByteArray
import com.burpmcp.ultra.core.EnumValidation
import burp.api.montoya.core.Registration
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.regex.Pattern

/**
 * Tracks a live Script-mode scan check deployed via the Montoya API.
 *
 * @property id Unique identifier (e.g. "scheck-001").
 * @property name Human-readable check name.
 * @property mode "passive" or "active".
 * @property config The full configuration used to create this check.
 * @property deployedAt ISO-8601 timestamp of deployment.
 * @property registration The Montoya [Registration] handle for deregistration.
 */
data class DeployedScanCheck(
    val id: String,
    val name: String,
    val mode: String,
    val config: JsonObject,
    val deployedAt: String,
    var registration: Registration? = null
)

/**
 * Bridge that creates and manages custom scan checks at runtime via the
 * Montoya API's [ScanCheck] interface.
 *
 * Script mode is the programmatic complement to BCheck (DSL-based). It
 * supports multi-step payload chains, conditional branching, response
 * analysis with capture groups, and complex consolidation logic.
 *
 * The agent describes the check as structured JSON parameters. This bridge
 * compiles the description into a live [ScanCheck] implementation and
 * registers it with Burp's scanner.
 */
class ScanCheckBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager
) {
    private val deployedChecks = CopyOnWriteArrayList<DeployedScanCheck>()

    /**
     * Create a PASSIVE scan check (Script mode).
     *
     * Runs on every response during scanning. Can match response body,
     * headers, status codes, request fields, and more. Supports multiple
     * conditions with AND logic and negation.
     *
     * @param name Unique name for the check / issue.
     * @param description What this check detects.
     * @param conditions List of condition objects, all must match (AND logic).
     *   Each condition: {location, pattern, condition_type, negate}.
     * @param severity Issue severity: high, medium, low, information.
     * @param confidence Issue confidence: certain, firm, tentative.
     * @param issueDetail Detailed description included in reported issues.
     * @param issueRemediation Remediation guidance (optional).
     * @return JSON object with deployment status or error.
     */
    fun createPassive(
        name: String,
        description: String,
        conditions: List<JsonObject>,
        severity: String,
        confidence: String,
        issueDetail: String,
        issueRemediation: String?
    ): JsonObject {
        return try {
            EnumValidation.error(severity, VALID_SEVERITIES, "severity", required = true)?.let { return it }
            EnumValidation.error(confidence, VALID_CONFIDENCES, "confidence", required = true)?.let { return it }
            validateConditions(conditions, "conditions")?.let { return it }
            val auditSeverity = parseSeverity(severity)
            val auditConfidence = parseConfidence(confidence)

            val scanCheck = object : ScanCheck {
                override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult {
                    val issues = mutableListOf<AuditIssue>()

                    // Evaluate all conditions -- all must match (AND)
                    val allMatch = conditions.isNotEmpty() && conditions.all { cond ->
                        evaluateCondition(cond, baseRequestResponse)
                    }

                    if (allMatch) {
                        val url = baseRequestResponse.request()?.url() ?: ""
                        val issue = AuditIssue.auditIssue(
                            name,
                            issueDetail,
                            issueRemediation ?: "Review and address the identified issue.",
                            url,
                            auditSeverity,
                            auditConfidence,
                            null,
                            null,
                            auditSeverity,
                            baseRequestResponse
                        )
                        issues.add(issue)
                    }

                    return AuditResult.auditResult(issues)
                }

                override fun activeAudit(
                    baseRequestResponse: HttpRequestResponse,
                    insertionPoint: AuditInsertionPoint
                ): AuditResult {
                    // Passive-only check -- no active audit behavior
                    return AuditResult.auditResult(emptyList())
                }

                override fun consolidateIssues(
                    existingIssue: AuditIssue,
                    newIssue: AuditIssue
                ): ConsolidationAction {
                    return if (existingIssue.name() == newIssue.name() &&
                        existingIssue.baseUrl() == newIssue.baseUrl()
                    ) {
                        ConsolidationAction.KEEP_EXISTING
                    } else {
                        ConsolidationAction.KEEP_BOTH
                    }
                }
            }

            val registration = api.scanner().registerScanCheck(scanCheck)

            val id = stateManager.generateId("scheck")
            val config = buildJsonObject {
                put("name", name)
                put("description", description)
                put("mode", "passive")
                put("conditions", buildJsonArray { conditions.forEach { add(it) } })
                put("severity", severity)
                put("confidence", confidence)
            }

            deployedChecks.add(DeployedScanCheck(id, name, "passive", config, Instant.now().toString(), registration))
            stateManager.registeredScanChecks.add(name)

            buildJsonObject {
                put("id", id)
                put("name", name)
                put("mode", "passive")
                put("status", "deployed")
                put("description", description)
                put("conditions_count", conditions.size)
                put("note", "Passive scan check active. It will analyze all responses during scanning and in proxy history.")
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to create passive scan check: ${e.message}")
            }
        }
    }

    /**
     * Create an ACTIVE scan check (Script mode).
     *
     * Injects payloads at insertion points and analyzes responses. Supports
     * multi-step checks: inject payload A, check response, inject payload B,
     * confirm. Steps are executed sequentially at each insertion point.
     *
     * @param name Unique name for the check / issue.
     * @param description What this check detects.
     * @param steps List of step objects executed in order. Each step:
     *   {payload, response_conditions[], stop_if_no_match}.
     * @param severity Issue severity: high, medium, low, information.
     * @param confidence Issue confidence: certain, firm, tentative.
     * @param issueDetail Detailed description included in reported issues.
     * @param issueRemediation Remediation guidance (optional).
     * @return JSON object with deployment status or error.
     */
    fun createActive(
        name: String,
        description: String,
        steps: List<JsonObject>,
        severity: String,
        confidence: String,
        issueDetail: String,
        issueRemediation: String?
    ): JsonObject {
        return try {
            EnumValidation.error(severity, VALID_SEVERITIES, "severity", required = true)?.let { return it }
            EnumValidation.error(confidence, VALID_CONFIDENCES, "confidence", required = true)?.let { return it }
            steps.forEachIndexed { i, step ->
                val rc = step["response_conditions"]?.jsonArray?.filterIsInstance<JsonObject>() ?: emptyList()
                validateConditions(rc, "steps[$i].response_conditions")?.let { return it }
            }
            val auditSeverity = parseSeverity(severity)
            val auditConfidence = parseConfidence(confidence)

            val scanCheck = object : ScanCheck {
                override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult {
                    // Active-only check -- no passive audit behavior
                    return AuditResult.auditResult(emptyList())
                }

                override fun activeAudit(
                    baseRequestResponse: HttpRequestResponse,
                    insertionPoint: AuditInsertionPoint
                ): AuditResult {
                    val issues = mutableListOf<AuditIssue>()
                    var allStepsPassed = true
                    val evidenceResponses = mutableListOf<HttpRequestResponse>()

                    for (step in steps) {
                        val payload = step["payload"]?.jsonPrimitive?.contentOrNull ?: continue
                        val stopIfNoMatch = step["stop_if_no_match"]?.jsonPrimitive?.booleanOrNull ?: true
                        val responseConditions = step["response_conditions"]?.jsonArray
                            ?.mapNotNull { elem ->
                                when (elem) {
                                    is JsonObject -> elem
                                    else -> null
                                }
                            } ?: emptyList()

                        // Build the modified request with payload at the insertion point
                        val modifiedRequest = insertionPoint.buildHttpRequestWithPayload(
                            BurpByteArray.byteArray(payload)
                        )

                        // Resolve the HTTP service from the base request
                        val httpService = baseRequestResponse.httpService() ?: continue

                        // Send the request
                        val checkResponse = try {
                            api.http().sendRequest(modifiedRequest.withService(httpService))
                        } catch (_: Exception) {
                            allStepsPassed = false
                            if (stopIfNoMatch) break else continue
                        }
                        evidenceResponses.add(checkResponse)

                        // Check response conditions for this step
                        if (responseConditions.isNotEmpty()) {
                            val stepMatched = responseConditions.all { cond ->
                                evaluateCondition(cond, checkResponse)
                            }

                            if (!stepMatched) {
                                allStepsPassed = false
                                if (stopIfNoMatch) break
                            }
                        }
                    }

                    if (allStepsPassed && steps.isNotEmpty()) {
                        val url = baseRequestResponse.request()?.url() ?: ""
                        // Include base and all evidence responses in the issue
                        val allEvidence = mutableListOf(baseRequestResponse)
                        allEvidence.addAll(evidenceResponses)
                        val issue = AuditIssue.auditIssue(
                            name,
                            issueDetail,
                            issueRemediation ?: "Review and address the identified issue.",
                            url,
                            auditSeverity,
                            auditConfidence,
                            null,
                            null,
                            auditSeverity,
                            *allEvidence.toTypedArray()
                        )
                        issues.add(issue)
                    }

                    return AuditResult.auditResult(issues)
                }

                override fun consolidateIssues(
                    existingIssue: AuditIssue,
                    newIssue: AuditIssue
                ): ConsolidationAction {
                    return if (existingIssue.name() == newIssue.name() &&
                        existingIssue.baseUrl() == newIssue.baseUrl()
                    ) {
                        ConsolidationAction.KEEP_EXISTING
                    } else {
                        ConsolidationAction.KEEP_BOTH
                    }
                }
            }

            val registration = api.scanner().registerScanCheck(scanCheck)

            val id = stateManager.generateId("scheck")
            val config = buildJsonObject {
                put("name", name)
                put("description", description)
                put("mode", "active")
                put("steps", buildJsonArray { steps.forEach { add(it) } })
                put("severity", severity)
                put("confidence", confidence)
            }

            deployedChecks.add(DeployedScanCheck(id, name, "active", config, Instant.now().toString(), registration))
            stateManager.registeredScanChecks.add(name)

            buildJsonObject {
                put("id", id)
                put("name", name)
                put("mode", "active")
                put("status", "deployed")
                put("description", description)
                put("steps_count", steps.size)
                put("note", "Active scan check deployed. It will inject payloads at insertion points during active scanning.")
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to create active scan check: ${e.message}")
            }
        }
    }

    /**
     * Lists all Script-mode scan checks deployed via this bridge.
     *
     * @return JSON object with count and array of deployed checks.
     */
    fun list(): JsonObject {
        return buildJsonObject {
            put("count", deployedChecks.size)
            put("checks", buildJsonArray {
                deployedChecks.forEach { check ->
                    add(buildJsonObject {
                        put("id", check.id)
                        put("name", check.name)
                        put("mode", check.mode)
                        put("deployed_at", check.deployedAt)
                    })
                }
            })
        }
    }

    /**
     * Removes a deployed Script-mode scan check by ID.
     *
     * Deregisters the check from Burp's scanner via the [Registration]
     * handle, then removes it from internal tracking.
     *
     * @param id The scan check ID (e.g. "scheck-001").
     * @return JSON object confirming removal or reporting an error.
     */
    fun remove(id: String): JsonObject {
        val check = deployedChecks.find { it.id == id }
            ?: return buildJsonObject { put("error", "Scan check not found: $id") }

        // Deregister via the Montoya Registration handle
        try {
            check.registration?.deregister()
        } catch (_: Exception) { }

        deployedChecks.removeIf { it.id == id }
        stateManager.registeredScanChecks.remove(check.name)

        return buildJsonObject {
            put("id", id)
            put("name", check.name)
            put("mode", check.mode)
            put("removed", true)
        }
    }

    /**
     * Returns Script-mode templates, examples, and a condition reference.
     *
     * Teaches the AI agent the full capabilities of Script mode: passive
     * and active check patterns, condition types, locations, and multi-step
     * payload chain examples.
     *
     * @return JSON object with templates and reference documentation.
     */
    fun getTemplates(): JsonObject {
        return buildJsonObject {
            put("mode", "script")
            put("description", "Script mode creates scan checks via the Montoya Java API at runtime. " +
                "More powerful than BCheck -- supports multi-step active checks, conditional payload " +
                "chains, programmatic response analysis, and custom consolidation logic.")
            put("when_to_use", "Use Script mode when you need: multi-step verification (inject A, " +
                "check, inject B, confirm), complex conditional logic, response comparison between " +
                "payloads, or custom consolidation rules. Use BCheck mode for simpler pattern matching.")

            put("passive_check_templates", buildJsonArray {
                add(buildJsonObject {
                    put("name", "Sensitive Data Exposure")
                    put("description", "Detect sensitive patterns in responses")
                    put("conditions_example", buildJsonArray {
                        add(buildJsonObject {
                            put("location", "response_body")
                            put("pattern", "(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token)\\s*[=:]\\s*['\"]?[a-zA-Z0-9]{20,}")
                            put("condition_type", "matches")
                            put("negate", false)
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "Security Header Missing")
                    put("description", "Check for missing security headers")
                    put("conditions_example", buildJsonArray {
                        add(buildJsonObject {
                            put("location", "response_headers")
                            put("pattern", "(?i)strict-transport-security")
                            put("condition_type", "matches")
                            put("negate", true)
                        })
                        add(buildJsonObject {
                            put("location", "status_code")
                            put("pattern", "200")
                            put("condition_type", "equals")
                            put("negate", false)
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "Error Message Disclosure")
                    put("description", "Detect stack traces and error details")
                    put("conditions_example", buildJsonArray {
                        add(buildJsonObject {
                            put("location", "response_body")
                            put("pattern", "(?i)(stack.?trace|exception|traceback|error.*line\\s*\\d+|at\\s+[a-z]+\\.[a-z]+\\.[a-z]+)")
                            put("condition_type", "matches")
                            put("negate", false)
                        })
                    })
                })
            })

            put("active_check_templates", buildJsonArray {
                add(buildJsonObject {
                    put("name", "SQL Injection (Error-based)")
                    put("description", "Multi-step: inject quote, check for SQL error, confirm with different payload")
                    put("steps_example", buildJsonArray {
                        add(buildJsonObject {
                            put("payload", "'")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "(?i)(sql|syntax|mysql|postgresql|oracle|sqlite|database|query)")
                                    put("condition_type", "matches")
                                    put("negate", false)
                                })
                            })
                        })
                        add(buildJsonObject {
                            put("payload", "' OR '1'='1")
                            put("stop_if_no_match", false)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "(?i)(sql|syntax|mysql|postgresql|oracle|sqlite|database|query)")
                                    put("condition_type", "matches")
                                    put("negate", false)
                                })
                            })
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "SSTI Detection (Multi-step)")
                    put("description", "Inject math expression, verify evaluation, confirm with different expression")
                    put("steps_example", buildJsonArray {
                        add(buildJsonObject {
                            put("payload", "{{7*7}}")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "49")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                        add(buildJsonObject {
                            put("payload", "{{7*6}}")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "42")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "Reflected XSS (Multi-step)")
                    put("description", "Inject canary, check reflection, inject XSS payload, verify unencoded reflection")
                    put("steps_example", buildJsonArray {
                        add(buildJsonObject {
                            put("payload", "burpmcp7x7canary")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "burpmcp7x7canary")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                        add(buildJsonObject {
                            put("payload", "<burpmcp>xss</burpmcp>")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "<burpmcp>xss</burpmcp>")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                    })
                })
            })

            put("condition_reference", buildJsonObject {
                put("locations", buildJsonArray {
                    add("response_body - HTTP response body text")
                    add("response_headers - All response headers as text")
                    add("status_code - HTTP status code as string")
                    add("response_length - Response body length as string")
                    add("request_body - HTTP request body text")
                    add("request_headers - All request headers as text")
                    add("request_url - Full request URL")
                })
                put("condition_types", buildJsonArray {
                    add("matches - Regex pattern match")
                    add("contains - Substring containment check")
                    add("equals - Exact string equality")
                })
                put("negate", "Set to true to invert the condition (NOT matches)")
                put("active_step_fields", buildJsonArray {
                    add("payload - String to inject at the insertion point")
                    add("response_conditions - Array of conditions to check on the response")
                    add("stop_if_no_match - If true, stop the chain if conditions don't match (default: true)")
                })
            })
        }
    }

    // ---------------------------------------------------------------
    // Helper methods
    // ---------------------------------------------------------------

    /**
     * Evaluates a single condition against an [HttpRequestResponse].
     *
     * @param condition JSON object with keys: location, pattern,
     *   condition_type (matches/contains/equals), negate (boolean).
     * @param requestResponse The request/response pair to evaluate against.
     * @return true if the condition matches (after applying negation).
     */
    private fun evaluateCondition(condition: JsonObject, requestResponse: HttpRequestResponse): Boolean {
        val location = condition["location"]?.jsonPrimitive?.contentOrNull ?: return false
        val pattern = condition["pattern"]?.jsonPrimitive?.contentOrNull ?: return false
        val conditionType = condition["condition_type"]?.jsonPrimitive?.contentOrNull ?: "matches"
        val negate = condition["negate"]?.jsonPrimitive?.booleanOrNull ?: false

        val text = when (location.lowercase()) {
            "response_body" -> requestResponse.response()?.bodyToString() ?: ""
            "response_headers" -> requestResponse.response()?.headers()
                ?.joinToString("\r\n") { "${it.name()}: ${it.value()}" } ?: ""
            "status_code" -> requestResponse.response()?.statusCode()?.toString() ?: ""
            "response_length" -> (requestResponse.response()?.body()?.length() ?: 0).toString()
            "request_body" -> requestResponse.request()?.bodyToString() ?: ""
            "request_headers" -> requestResponse.request()?.headers()
                ?.joinToString("\r\n") { "${it.name()}: ${it.value()}" } ?: ""
            "request_url" -> requestResponse.request()?.url() ?: ""
            else -> ""
        }

        val result = when (conditionType.lowercase()) {
            "contains" -> text.contains(pattern, ignoreCase = true)
            "equals" -> text.equals(pattern, ignoreCase = true)
            "matches" -> {
                try {
                    Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(text).find()
                } catch (_: Exception) {
                    // Fallback: treat as substring match if regex is invalid
                    text.contains(pattern, ignoreCase = true)
                }
            }
            else -> false
        }

        return if (negate) !result else result
    }

    private fun parseSeverity(s: String): AuditIssueSeverity {
        return when (s.lowercase()) {
            "high" -> AuditIssueSeverity.HIGH
            "medium" -> AuditIssueSeverity.MEDIUM
            "low" -> AuditIssueSeverity.LOW
            "information", "info" -> AuditIssueSeverity.INFORMATION
            else -> AuditIssueSeverity.MEDIUM
        }
    }

    private fun parseConfidence(c: String): AuditIssueConfidence {
        return when (c.lowercase()) {
            "certain" -> AuditIssueConfidence.CERTAIN
            "firm" -> AuditIssueConfidence.FIRM
            "tentative" -> AuditIssueConfidence.TENTATIVE
            else -> AuditIssueConfidence.TENTATIVE
        }
    }

    private val VALID_LOCATIONS = setOf(
        "response_body", "response_headers", "status_code", "response_length",
        "request_body", "request_headers", "request_url"
    )
    private val VALID_CONDITION_TYPES = setOf("contains", "equals", "matches")
    private val VALID_SEVERITIES = setOf("high", "medium", "low", "information", "info")
    private val VALID_CONFIDENCES = setOf("certain", "firm", "tentative")

    /**
     * Rejects scan-check conditions whose location/condition_type are not recognised, so a
     * mistyped rule fails at registration instead of silently never firing (or, with negate,
     * firing on every request). condition_type is optional (defaults to "matches").
     */
    private fun validateConditions(conditions: List<JsonObject>, prefix: String): JsonObject? {
        conditions.forEachIndexed { i, c ->
            val loc = c["location"]?.jsonPrimitive?.contentOrNull
            EnumValidation.error(loc, VALID_LOCATIONS, "$prefix[$i].location", required = true)?.let { return it }
            val ct = c["condition_type"]?.jsonPrimitive?.contentOrNull
            EnumValidation.error(ct, VALID_CONDITION_TYPES, "$prefix[$i].condition_type")?.let { return it }
        }
        return null
    }
}
