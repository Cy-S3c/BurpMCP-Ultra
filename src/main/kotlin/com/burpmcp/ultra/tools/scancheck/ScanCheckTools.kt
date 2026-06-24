package com.burpmcp.ultra.tools.scancheck

import com.burpmcp.ultra.bridge.ScanCheckBridge
import com.burpmcp.ultra.core.asJsonObjectList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers all 5 Script-mode scan check MCP tools onto the given [Server].
 *
 * Script mode uses the Montoya API's ScanCheck interface to create runtime
 * scan checks with full programmatic control. Unlike BCheck (DSL-based),
 * Script mode supports multi-step payload chains, conditional branching,
 * response analysis with capture groups, and complex consolidation logic.
 */
object ScanCheckTools {

    fun register(server: Server, bridge: ScanCheckBridge) {

        // ---------------------------------------------------------------
        // 1. scancheck_create_passive
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_create_passive",
            description = "Create a passive Script-mode scan check that analyzes every response during " +
                "scanning. More powerful than BCheck -- supports multiple conditions with AND logic, " +
                "negation, and regex/contains/equals matching across response body, headers, status " +
                "code, request fields, and more. Parameters: name (required, check name), description " +
                "(required, what it detects), conditions (required, array of condition objects -- each " +
                "with: location [response_body, response_headers, status_code, response_length, " +
                "request_body, request_headers, request_url], pattern [regex or string], condition_type " +
                "[matches, contains, equals], negate [true/false]), severity (required: high, medium, " +
                "low, information), confidence (required: certain, firm, tentative), issue_detail " +
                "(required, detailed issue description), issue_remediation (optional, how to fix). " +
                "Use scancheck_templates first to see examples and the full condition reference.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Check name") }
                    putJsonObject("description") { put("type", "string"); put("description", "What the check detects") }
                    putJsonObject("conditions") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "Condition objects: location, pattern, condition_type, negate") }
                    putJsonObject("severity") { put("type", "string"); put("description", "Severity: high, medium, low, information") }
                    putJsonObject("confidence") { put("type", "string"); put("description", "Confidence: certain, firm, tentative") }
                    putJsonObject("issue_detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("issue_remediation") { put("type", "string"); put("description", "How to fix the issue") }
                },
                required = listOf("name", "description", "conditions", "severity", "confidence", "issue_detail")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val name = args["name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: name")
                        }.toString())),
                        isError = true
                    )

                val description = args["description"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: description")
                        }.toString())),
                        isError = true
                    )

                val conditions = args["conditions"]?.asJsonObjectList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: conditions (array of {location, pattern, condition_type, negate})")
                        }.toString())),
                        isError = true
                    )

                val severity = args["severity"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: severity (high, medium, low, information)")
                        }.toString())),
                        isError = true
                    )

                val confidence = args["confidence"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: confidence (certain, firm, tentative)")
                        }.toString())),
                        isError = true
                    )

                val issueDetail = args["issue_detail"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: issue_detail")
                        }.toString())),
                        isError = true
                    )

                val issueRemediation = args["issue_remediation"]?.jsonPrimitive?.contentOrNull

                val result = bridge.createPassive(
                    name = name,
                    description = description,
                    conditions = conditions,
                    severity = severity,
                    confidence = confidence,
                    issueDetail = issueDetail,
                    issueRemediation = issueRemediation
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 2. scancheck_create_active
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_create_active",
            description = "Create an active Script-mode scan check that injects payloads at insertion " +
                "points during active scanning. Supports multi-step payload chains: inject payload A, " +
                "check response, inject payload B, confirm. More powerful than BCheck for complex " +
                "injection detection. Parameters: name (required, check name), description (required, " +
                "what it detects), steps (required, array of step objects -- each with: payload [string " +
                "to inject], response_conditions [array of condition objects like passive checks], " +
                "stop_if_no_match [boolean, default true -- stop chain if conditions fail]), severity " +
                "(required: high, medium, low, information), confidence (required: certain, firm, " +
                "tentative), issue_detail (required, detailed issue description), issue_remediation " +
                "(optional, how to fix). Use scancheck_templates first to see multi-step examples.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Check name") }
                    putJsonObject("description") { put("type", "string"); put("description", "What the check detects") }
                    putJsonObject("steps") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "Step objects: payload, response_conditions[], stop_if_no_match") }
                    putJsonObject("severity") { put("type", "string"); put("description", "Severity: high, medium, low, information") }
                    putJsonObject("confidence") { put("type", "string"); put("description", "Confidence: certain, firm, tentative") }
                    putJsonObject("issue_detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("issue_remediation") { put("type", "string"); put("description", "How to fix the issue") }
                },
                required = listOf("name", "description", "steps", "severity", "confidence", "issue_detail")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val name = args["name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: name")
                        }.toString())),
                        isError = true
                    )

                val description = args["description"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: description")
                        }.toString())),
                        isError = true
                    )

                val steps = args["steps"]?.asJsonObjectList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: steps (array of {payload, response_conditions[], stop_if_no_match})")
                        }.toString())),
                        isError = true
                    )

                val severity = args["severity"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: severity (high, medium, low, information)")
                        }.toString())),
                        isError = true
                    )

                val confidence = args["confidence"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: confidence (certain, firm, tentative)")
                        }.toString())),
                        isError = true
                    )

                val issueDetail = args["issue_detail"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: issue_detail")
                        }.toString())),
                        isError = true
                    )

                val issueRemediation = args["issue_remediation"]?.jsonPrimitive?.contentOrNull

                val result = bridge.createActive(
                    name = name,
                    description = description,
                    steps = steps,
                    severity = severity,
                    confidence = confidence,
                    issueDetail = issueDetail,
                    issueRemediation = issueRemediation
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 3. scancheck_templates
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_templates",
            description = "Get Script-mode scan check templates, examples, and full condition reference. " +
                "Returns passive and active check templates with realistic examples (sensitive data " +
                "exposure, missing security headers, error disclosure, SQL injection, SSTI, reflected " +
                "XSS), plus a complete reference of condition locations, types, and active step fields. " +
                "Call this BEFORE creating Script-mode checks to understand the capabilities and " +
                "correct parameter structure. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.getTemplates()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 4. scancheck_list
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_list",
            description = "List all Script-mode scan checks deployed via MCP. Returns the count and " +
                "details of each deployed check including its ID, name, mode (passive/active), and " +
                "deployment timestamp. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.list()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 5. scancheck_remove
        // ---------------------------------------------------------------
        server.addTool(
            name = "scancheck_remove",
            description = "Remove a deployed Script-mode scan check by its ID. This fully deregisters " +
                "the check from Burp's scanner -- unlike BCheck removal, Script-mode checks are " +
                "completely removed at runtime. Parameters: id (required, the scan check ID returned " +
                "by scancheck_create_passive or scancheck_create_active, e.g. 'scheck-001').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("id") { put("type", "string"); put("description", "Scan check ID to remove") }
                },
                required = listOf("id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val id = args["id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Missing required parameter: id")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.remove(id)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }
    }
}
