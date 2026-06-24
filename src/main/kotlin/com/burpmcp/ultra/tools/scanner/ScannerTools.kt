package com.burpmcp.ultra.tools.scanner

import com.burpmcp.ultra.bridge.ScannerBridge
import com.burpmcp.ultra.core.asStringList
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers all 13 scanner MCP tools onto the given [Server].
 *
 * Each tool delegates to the [ScannerBridge] and catches exceptions so
 * that errors are returned as structured JSON inside a [CallToolResult]
 * rather than propagating unhandled.
 */
object ScannerTools {

    fun register(server: Server, bridge: ScannerBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. scanner_start_crawl
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_start_crawl",
            description = "Start a web crawl against one or more target URLs. Returns a task ID for tracking progress. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("urls") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Target URLs to crawl") }
                    putJsonObject("max_depth") { put("type", "integer"); put("description", "Maximum crawl depth") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict crawl to in-scope URLs") }
                },
                required = listOf("urls")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val urls = args["urls"].asStringList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'urls' is required (array of URL strings)")
                        }.toString())),
                        isError = true
                    )

                val maxDepth = args["max_depth"]?.jsonPrimitive?.intOrNull
                val inScopeOnly = args["in_scope_only"]?.jsonPrimitive?.booleanOrNull ?: false

                val result = bridge.startCrawl(urls, maxDepth, inScopeOnly)
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
        // 2. scanner_start_audit
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_start_audit",
            description = "Start an active audit (vulnerability scan) against target URLs or specific HTTP requests. Supports light, normal, and thorough audit modes. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("urls") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Target URLs to audit") }
                    putJsonObject("requests") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Base64-encoded HTTP requests to audit") }
                    putJsonObject("audit_mode") { put("type", "string"); put("description", "Audit mode: light, normal, or thorough") }
                    putJsonObject("crawl_first") { put("type", "boolean"); put("description", "Crawl targets before auditing") }
                    putJsonObject("insertion_point_types") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Insertion point types to audit") }
                    putJsonObject("auth_header_name") { put("type", "string"); put("description", "Authentication header name") }
                    putJsonObject("auth_header_value") { put("type", "string"); put("description", "Authentication header value") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val urls = args["urls"].asStringList()
                val requests = args["requests"].asStringList()

                if (urls.isNullOrEmpty() && requests.isNullOrEmpty()) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "At least one of 'urls' or 'requests' must be provided")
                        }.toString())),
                        isError = true
                    )
                }

                val auditMode = args["audit_mode"]?.jsonPrimitive?.contentOrNull
                val crawlFirst = args["crawl_first"]?.jsonPrimitive?.booleanOrNull ?: true
                val insertionPointTypes = args["insertion_point_types"].asStringList()
                val authHeaderName = args["auth_header_name"]?.jsonPrimitive?.contentOrNull
                val authHeaderValue = args["auth_header_value"]?.jsonPrimitive?.contentOrNull

                val result = bridge.startAudit(urls, requests, auditMode, crawlFirst, insertionPointTypes, authHeaderName, authHeaderValue)
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
        // 3. scanner_task_status
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_status",
            description = "Get the current status of a scanner task including request count, error count, and issue count.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("task_id") { put("type", "string"); put("description", "Scanner task ID") }
                },
                required = listOf("task_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId = args["task_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'task_id' is required")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.getTaskStatus(taskId)
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
        // 4. scanner_task_list
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_list",
            description = "List all scanner tasks (crawl and audit), optionally filtered by status.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("status") { put("type", "string"); put("description", "Filter tasks by status") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val status = args["status"]?.jsonPrimitive?.contentOrNull

                val result = bridge.listTasks(status)
                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("task_count", result.size)
                    put("tasks", result)
                }.toString())))
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
        // 5. scanner_task_delete
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_delete",
            description = "Cancel and delete a scanner task by its task ID.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("task_id") { put("type", "string"); put("description", "Scanner task ID") }
                },
                required = listOf("task_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId = args["task_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'task_id' is required")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.deleteTask(taskId)
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
        // 6. scanner_task_add_request
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_add_request",
            description = "Add an HTTP request to an existing audit task for scanning. The request must be base64-encoded.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("task_id") { put("type", "string"); put("description", "Audit task ID") }
                    putJsonObject("request") { put("type", "string"); put("description", "Base64-encoded HTTP request") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target host") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Use TLS for the request") }
                },
                required = listOf("task_id", "request")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val taskId = args["task_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'task_id' is required")
                        }.toString())),
                        isError = true
                    )

                val reqData = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'request' is required (base64-encoded HTTP request)")
                        }.toString())),
                        isError = true
                    )

                val host = args["host"]?.jsonPrimitive?.contentOrNull
                val port = args["port"]?.jsonPrimitive?.intOrNull
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull

                val result = bridge.addRequestToTask(taskId, reqData, host, port, useTls)
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
        // 7. scanner_task_issues
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_task_issues",
            description = "Get all issues found by a specific audit task.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("task_id") { put("type", "string"); put("description", "Audit task ID") }
                },
                required = listOf("task_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val taskId = args["task_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'task_id' is required")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.getTaskIssues(taskId)
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
        // 8. scanner_get_all_issues
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_get_all_issues",
            description = "Get all scanner issues from the site map with optional filtering by URL prefix, severity, and confidence.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "URL prefix filter") }
                    putJsonObject("severity") { put("type", "string"); put("description", "Severity filter") }
                    putJsonObject("confidence") { put("type", "string"); put("description", "Confidence filter") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum number of issues to return") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val severity = args["severity"]?.jsonPrimitive?.contentOrNull
                val confidence = args["confidence"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull

                val result = bridge.getAllIssues(urlPrefix, severity, confidence, maxResults)
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
        // 9. scanner_generate_report
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_generate_report",
            description = "Generate a scan report in HTML or XML format. Can filter by URL prefix and severity levels. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("format") { put("type", "string"); put("description", "Report format: HTML or XML") }
                    putJsonObject("output_path") { put("type", "string"); put("description", "Report output filename") }
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "URL prefix filter") }
                    putJsonObject("severity_filter") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Severities to include") }
                },
                required = listOf("output_path")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val format = args["format"]?.jsonPrimitive?.contentOrNull ?: "HTML"

                val outputPath = args["output_path"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'output_path' is required")
                        }.toString())),
                        isError = true
                    )

                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val severityFilter = args["severity_filter"]?.let { it as? JsonArray }
                    ?.map { it.jsonPrimitive.content }

                val result = bridge.generateReport(format, urlPrefix, severityFilter, outputPath)
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
        // 10. scanner_create_issue
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_create_issue",
            description = "Create a custom audit issue and add it to the site map. Useful for manual findings or integration with external tools.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Issue name") }
                    putJsonObject("detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("remediation") { put("type", "string"); put("description", "Remediation guidance") }
                    putJsonObject("severity") { put("type", "string"); put("description", "Issue severity") }
                    putJsonObject("confidence") { put("type", "string"); put("description", "Issue confidence") }
                    putJsonObject("url") { put("type", "string"); put("description", "Affected URL") }
                    putJsonObject("request") { put("type", "string"); put("description", "Associated HTTP request") }
                    putJsonObject("response") { put("type", "string"); put("description", "Associated HTTP response") }
                },
                required = listOf("name", "url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val name = args["name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'name' is required")
                        }.toString())),
                        isError = true
                    )

                val detail = args["detail"]?.jsonPrimitive?.contentOrNull
                val remediation = args["remediation"]?.jsonPrimitive?.contentOrNull

                val severity = args["severity"]?.jsonPrimitive?.contentOrNull ?: "INFORMATION"
                val confidence = args["confidence"]?.jsonPrimitive?.contentOrNull ?: "TENTATIVE"

                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'url' is required")
                        }.toString())),
                        isError = true
                    )

                val reqData = args["request"]?.jsonPrimitive?.contentOrNull
                val respData = args["response"]?.jsonPrimitive?.contentOrNull

                val result = bridge.createCustomIssue(
                    name, detail, remediation, severity, confidence, url, reqData, respData
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
        // 11. scanner_import_bcheck
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_import_bcheck",
            description = "Import a BCheck script into the Burp Suite scanner. BChecks define custom scan checks in Burp's domain-specific language. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("script") { put("type", "string"); put("description", "BCheck script content") }
                },
                required = listOf("script")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val script = args["script"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'script' is required (BCheck script content)")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.importBCheck(script)
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
        // 12. scanner_register_check
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_register_check",
            description = "Register a custom scan check (passive or active) that matches response content and reports issues. " +
                "Passive checks use regex matching against response body/headers. " +
                "Active checks inject payloads at insertion points and match response content. " +
                "Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("check_name") { put("type", "string"); put("description", "Name of the scan check") }
                    putJsonObject("check_type") { put("type", "string"); put("description", "Check type: passive or active") }
                    putJsonObject("issue_name") { put("type", "string"); put("description", "Name of the reported issue") }
                    putJsonObject("issue_severity") { put("type", "string"); put("description", "Issue severity") }
                    putJsonObject("issue_confidence") { put("type", "string"); put("description", "Issue confidence") }
                    putJsonObject("issue_detail") { put("type", "string"); put("description", "Detailed issue description") }
                    putJsonObject("issue_remediation") { put("type", "string"); put("description", "Remediation guidance") }
                    putJsonObject("passive_response_match") { put("type", "string"); put("description", "Regex matched against response body for passive checks") }
                    putJsonObject("passive_header_match") { put("type", "string"); put("description", "Regex matched against response headers for passive checks") }
                    putJsonObject("active_payloads") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Payloads to inject for active checks") }
                    putJsonObject("active_response_match") { put("type", "string"); put("description", "Response content to match after injection") }
                    putJsonObject("active_grep_match") { put("type", "string"); put("description", "Alias for active_response_match") }
                },
                required = listOf("check_name", "issue_name")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val checkName = args["check_name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'check_name' is required")
                        }.toString())),
                        isError = true
                    )

                val checkType = args["check_type"]?.jsonPrimitive?.contentOrNull ?: "passive"

                val issueName = args["issue_name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'issue_name' is required")
                        }.toString())),
                        isError = true
                    )

                val issueSeverity = args["issue_severity"]?.jsonPrimitive?.contentOrNull ?: "INFORMATION"
                val issueConfidence = args["issue_confidence"]?.jsonPrimitive?.contentOrNull ?: "TENTATIVE"
                val issueDetail = args["issue_detail"]?.jsonPrimitive?.contentOrNull ?: ""
                val issueRemediation = args["issue_remediation"]?.jsonPrimitive?.contentOrNull ?: ""

                val passiveResponseMatch = args["passive_response_match"]?.jsonPrimitive?.contentOrNull
                val passiveHeaderMatch = args["passive_header_match"]?.jsonPrimitive?.contentOrNull
                val activePayloads = args["active_payloads"].asStringList()
                val activeResponseMatch = args["active_response_match"]?.jsonPrimitive?.contentOrNull
                // active_grep_match is accepted as an alias for active_response_match
                val effectiveActiveResponseMatch = activeResponseMatch
                    ?: args["active_grep_match"]?.jsonPrimitive?.contentOrNull

                val result = bridge.registerScanCheck(
                    checkName = checkName,
                    checkType = checkType,
                    issueName = issueName,
                    severity = issueSeverity,
                    confidence = issueConfidence,
                    detail = issueDetail,
                    remediation = issueRemediation,
                    passiveResponseMatch = passiveResponseMatch,
                    passiveHeaderMatch = passiveHeaderMatch,
                    activePayloads = activePayloads,
                    activeResponseMatch = effectiveActiveResponseMatch
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
        // 13. scanner_unregister_check
        // ---------------------------------------------------------------
        server.addTool(
            name = "scanner_unregister_check",
            description = "Deregister a custom scan check previously created with scanner_register_check, " +
                "removing it from Burp's scanner. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("check_name") { put("type", "string"); put("description", "Name of the scan check to remove (as used when registering)") }
                },
                required = listOf("check_name")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val checkName = args["check_name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'check_name' is required")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.unregisterScanCheck(checkName)
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
