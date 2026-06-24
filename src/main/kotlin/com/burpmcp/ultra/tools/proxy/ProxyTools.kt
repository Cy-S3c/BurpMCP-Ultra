package com.burpmcp.ultra.tools.proxy

import com.burpmcp.ultra.bridge.ProxyBridge
import com.burpmcp.ultra.state.ProxyRule
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers all 13 proxy MCP tools onto the given [Server].
 *
 * Each tool delegates to the [ProxyBridge] and catches exceptions so
 * that errors are returned as structured JSON inside a [CallToolResult]
 * rather than propagating unhandled.
 */
object ProxyTools {

    fun register(server: Server, bridge: ProxyBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. proxy_history
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_history",
            description = "Get HTTP proxy history entries with optional filtering by host, method, status code, status code range, MIME type. Returns request/response metadata and optionally full request/response text.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("start_index") { put("type", "integer"); put("description", "Start index of history entries (default 0)") }
                    putJsonObject("count") { put("type", "integer"); put("description", "Maximum number of entries to return (default 100)") }
                    putJsonObject("host") { put("type", "string"); put("description", "Filter by host") }
                    putJsonObject("method") { put("type", "string"); put("description", "Filter by HTTP method") }
                    putJsonObject("status_code") { put("type", "integer"); put("description", "Filter by exact status code") }
                    putJsonObject("status_code_range") { put("type", "string"); put("description", "Filter by status code range") }
                    putJsonObject("mime_type") { put("type", "string"); put("description", "Filter by MIME type") }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text (default false)") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text (default false)") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict to in-scope items (default false)") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response text to this length") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val startIndex = args["start_index"]?.jsonPrimitive?.intOrNull ?: 0
                val count = args["count"]?.jsonPrimitive?.intOrNull ?: 100
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                val method = args["method"]?.jsonPrimitive?.contentOrNull
                val statusCode = args["status_code"]?.jsonPrimitive?.intOrNull
                val statusCodeRange = args["status_code_range"]?.jsonPrimitive?.contentOrNull
                val mimeType = args["mime_type"]?.jsonPrimitive?.contentOrNull
                val includeRequest = args["include_request"]?.jsonPrimitive?.booleanOrNull ?: false
                val includeResponse = args["include_response"]?.jsonPrimitive?.booleanOrNull ?: false
                val inScopeOnly = args["in_scope_only"]?.jsonPrimitive?.booleanOrNull ?: false
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull

                val result = bridge.getHistory(
                    startIndex, count, host, method, statusCode, mimeType,
                    inScopeOnly, includeRequest, includeResponse, statusCodeRange, maxResponseLength
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
        // 2. proxy_history_search
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_history_search",
            description = "Search proxy history using a regex pattern. Can search in request, response, or both. Returns matching history entries.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex pattern to search for") }
                    putJsonObject("search_in") { put("type", "string"); put("description", "Where to search: 'request', 'response', or 'both' (default 'both')") }
                    putJsonObject("case_sensitive") { put("type", "boolean"); put("description", "Case-sensitive matching (default false)") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum number of results (default 100)") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict to in-scope items (default false)") }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text (default false)") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text (default false)") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response text to this length") }
                },
                required = listOf("pattern")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val pattern = args["pattern"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'pattern' is required")
                        }.toString())),
                        isError = true
                    )

                val searchIn = args["search_in"]?.jsonPrimitive?.contentOrNull ?: "both"
                val caseSensitive = args["case_sensitive"]?.jsonPrimitive?.booleanOrNull ?: false
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 100
                val inScopeOnly = args["in_scope_only"]?.jsonPrimitive?.booleanOrNull ?: false
                val includeRequest = args["include_request"]?.jsonPrimitive?.booleanOrNull ?: false
                val includeResponse = args["include_response"]?.jsonPrimitive?.booleanOrNull ?: false
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull

                val result = bridge.searchHistory(
                    pattern, searchIn, caseSensitive, maxResults, inScopeOnly,
                    includeRequest, includeResponse, maxResponseLength
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
        // 3. proxy_websocket_history
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_websocket_history",
            description = "Get WebSocket proxy history entries with optional filtering by host and direction (CLIENT_TO_SERVER or SERVER_TO_CLIENT).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("start_index") { put("type", "integer"); put("description", "Start index of history entries (default 0)") }
                    putJsonObject("count") { put("type", "integer"); put("description", "Maximum number of entries to return (default 100)") }
                    putJsonObject("host") { put("type", "string"); put("description", "Filter by host") }
                    putJsonObject("direction") { put("type", "string"); put("description", "Filter by direction (CLIENT_TO_SERVER or SERVER_TO_CLIENT)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val startIndex = args["start_index"]?.jsonPrimitive?.intOrNull ?: 0
                val count = args["count"]?.jsonPrimitive?.intOrNull ?: 100
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                val direction = args["direction"]?.jsonPrimitive?.contentOrNull

                val result = bridge.getWebSocketHistory(startIndex, count, host, direction)
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
        // 4. proxy_websocket_history_search
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_websocket_history_search",
            description = "Search WebSocket proxy history using a regex pattern on message payloads. Can filter by direction.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex pattern to search message payloads") }
                    putJsonObject("direction") { put("type", "string"); put("description", "Filter by direction (CLIENT_TO_SERVER or SERVER_TO_CLIENT)") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum number of results (default 100)") }
                },
                required = listOf("pattern")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val pattern = args["pattern"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'pattern' is required")
                        }.toString())),
                        isError = true
                    )

                val direction = args["direction"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 100

                val result = bridge.searchWebSocketHistory(pattern, direction, maxResults)
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
        // 5. proxy_intercept_enable
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_enable",
            description = "Enable proxy interception. When enabled, requests/responses will be held for review before forwarding.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.enableIntercept()
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
        // 6. proxy_intercept_disable
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_disable",
            description = "Disable proxy interception. Requests/responses will pass through without being held.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.disableIntercept()
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
        // 7. proxy_intercept_status
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_intercept_status",
            description = "Get the current proxy interception state (enabled or disabled).",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.isInterceptEnabled()
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
        // 8. proxy_annotate
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_annotate",
            description = "Annotate a proxy history item by setting a comment and/or highlight color. Highlight colors: NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("index") { put("type", "integer"); put("description", "Proxy history item ID") }
                    putJsonObject("comment") { put("type", "string"); put("description", "Comment to set on the item") }
                    putJsonObject("highlight") { put("type", "string"); put("description", "Highlight color (NONE, RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY)") }
                },
                required = listOf("index")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val index = args["index"]?.jsonPrimitive?.intOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'index' is required (proxy history item ID)")
                        }.toString())),
                        isError = true
                    )

                val comment = args["comment"]?.jsonPrimitive?.contentOrNull
                val highlight = args["highlight"]?.jsonPrimitive?.contentOrNull

                val result = bridge.annotateHistoryItem(index, comment, highlight)
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
        // 9. proxy_set_request_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_set_request_rule",
            description = "Set a proxy request interception rule. Rules can match on host, URL, method, header, or body patterns and perform actions: 'modify' (add/remove/replace headers, body regex replacement), 'drop' (silently drop the request), or 'tag' (annotate in proxy history). If rule_id matches an existing rule, it is replaced.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Rule ID; auto-generated if omitted") }
                    putJsonObject("action") { put("type", "string"); put("description", "Action: 'modify', 'drop', or 'tag'") }
                    putJsonObject("match_host") { put("type", "string"); put("description", "Regex to match against host") }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Regex to match against URL") }
                    putJsonObject("match_method") { put("type", "string"); put("description", "Regex to match against HTTP method") }
                    putJsonObject("match_header") { put("type", "string"); put("description", "Regex to match against headers") }
                    putJsonObject("match_body") { put("type", "string"); put("description", "Regex to match against body") }
                    putJsonObject("modify_add_header") { put("type", "string"); put("description", "Header to add when action is 'modify'") }
                    putJsonObject("modify_remove_header") { put("type", "string"); put("description", "Header to remove when action is 'modify'") }
                    putJsonObject("modify_replace_header") { put("type", "object"); put("description", "Map of header names to replacement values") }
                    putJsonObject("modify_body_regex") { put("type", "string"); put("description", "Regex for body replacement") }
                    putJsonObject("modify_body_replacement") { put("type", "string"); put("description", "Replacement for body regex matches") }
                    putJsonObject("tag_comment") { put("type", "string"); put("description", "Comment to attach when action is 'tag'") }
                    putJsonObject("tag_highlight") { put("type", "string"); put("description", "Highlight color when action is 'tag'") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val ruleId = args["rule_id"]?.jsonPrimitive?.contentOrNull
                    ?: stateManager.generateId("prule")

                val action = args["action"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'action' is required ('modify', 'drop', or 'tag')")
                        }.toString())),
                        isError = true
                    )

                val replaceHeader = args["modify_replace_header"]?.jsonObject?.let { obj ->
                    obj.entries.associate { (k, v) -> k to v.jsonPrimitive.content }
                }

                val rule = ProxyRule(
                    ruleId = ruleId,
                    type = "request",
                    matchHost = args["match_host"]?.jsonPrimitive?.contentOrNull,
                    matchUrl = args["match_url"]?.jsonPrimitive?.contentOrNull,
                    matchMethod = args["match_method"]?.jsonPrimitive?.contentOrNull,
                    matchHeader = args["match_header"]?.jsonPrimitive?.contentOrNull,
                    matchBody = args["match_body"]?.jsonPrimitive?.contentOrNull,
                    matchStatus = null,
                    action = action,
                    modifyAddHeader = args["modify_add_header"]?.jsonPrimitive?.contentOrNull,
                    modifyRemoveHeader = args["modify_remove_header"]?.jsonPrimitive?.contentOrNull,
                    modifyReplaceHeader = replaceHeader,
                    modifyBodyRegex = args["modify_body_regex"]?.jsonPrimitive?.contentOrNull,
                    modifyBodyReplacement = args["modify_body_replacement"]?.jsonPrimitive?.contentOrNull,
                    tagComment = args["tag_comment"]?.jsonPrimitive?.contentOrNull,
                    tagHighlight = args["tag_highlight"]?.jsonPrimitive?.contentOrNull,
                    enabled = args["enabled"]?.jsonPrimitive?.booleanOrNull ?: true
                )

                // Remove existing rule with same ID, then add the new one
                stateManager.proxyRules.removeIf { it.ruleId == ruleId }
                stateManager.proxyRules.add(rule)

                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("rule_set", true)
                    put("rule_id", ruleId)
                    put("type", "request")
                    put("action", action)
                    put("total_rules", stateManager.proxyRules.size)
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
        // 10. proxy_set_response_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_set_response_rule",
            description = "Set a proxy response interception rule. Rules can match on host, URL, status code, header, or body patterns and perform actions: 'modify' (add/remove/replace headers, body regex replacement), 'drop' (silently drop the response), or 'tag' (annotate in proxy history). If rule_id matches an existing rule, it is replaced.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Rule ID; auto-generated if omitted") }
                    putJsonObject("action") { put("type", "string"); put("description", "Action: 'modify', 'drop', or 'tag'") }
                    putJsonObject("match_host") { put("type", "string"); put("description", "Regex to match against host") }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Regex to match against URL") }
                    putJsonObject("match_header") { put("type", "string"); put("description", "Regex to match against headers") }
                    putJsonObject("match_body") { put("type", "string"); put("description", "Regex to match against body") }
                    putJsonObject("match_status") { put("type", "integer"); put("description", "Status code to match") }
                    putJsonObject("modify_add_header") { put("type", "string"); put("description", "Header to add when action is 'modify'") }
                    putJsonObject("modify_remove_header") { put("type", "string"); put("description", "Header to remove when action is 'modify'") }
                    putJsonObject("modify_replace_header") { put("type", "object"); put("description", "Map of header names to replacement values") }
                    putJsonObject("modify_body_regex") { put("type", "string"); put("description", "Regex for body replacement") }
                    putJsonObject("modify_body_replacement") { put("type", "string"); put("description", "Replacement for body regex matches") }
                    putJsonObject("tag_comment") { put("type", "string"); put("description", "Comment to attach when action is 'tag'") }
                    putJsonObject("tag_highlight") { put("type", "string"); put("description", "Highlight color when action is 'tag'") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val ruleId = args["rule_id"]?.jsonPrimitive?.contentOrNull
                    ?: stateManager.generateId("prule")

                val action = args["action"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'action' is required ('modify', 'drop', or 'tag')")
                        }.toString())),
                        isError = true
                    )

                val replaceHeader = args["modify_replace_header"]?.jsonObject?.let { obj ->
                    obj.entries.associate { (k, v) -> k to v.jsonPrimitive.content }
                }

                val rule = ProxyRule(
                    ruleId = ruleId,
                    type = "response",
                    matchHost = args["match_host"]?.jsonPrimitive?.contentOrNull,
                    matchUrl = args["match_url"]?.jsonPrimitive?.contentOrNull,
                    matchMethod = null,
                    matchHeader = args["match_header"]?.jsonPrimitive?.contentOrNull,
                    matchBody = args["match_body"]?.jsonPrimitive?.contentOrNull,
                    matchStatus = args["match_status"]?.jsonPrimitive?.intOrNull,
                    action = action,
                    modifyAddHeader = args["modify_add_header"]?.jsonPrimitive?.contentOrNull,
                    modifyRemoveHeader = args["modify_remove_header"]?.jsonPrimitive?.contentOrNull,
                    modifyReplaceHeader = replaceHeader,
                    modifyBodyRegex = args["modify_body_regex"]?.jsonPrimitive?.contentOrNull,
                    modifyBodyReplacement = args["modify_body_replacement"]?.jsonPrimitive?.contentOrNull,
                    tagComment = args["tag_comment"]?.jsonPrimitive?.contentOrNull,
                    tagHighlight = args["tag_highlight"]?.jsonPrimitive?.contentOrNull,
                    enabled = args["enabled"]?.jsonPrimitive?.booleanOrNull ?: true
                )

                // Remove existing rule with same ID, then add the new one
                stateManager.proxyRules.removeIf { it.ruleId == ruleId }
                stateManager.proxyRules.add(rule)

                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("rule_set", true)
                    put("rule_id", ruleId)
                    put("type", "response")
                    put("action", action)
                    put("total_rules", stateManager.proxyRules.size)
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
        // 11. proxy_list_rules
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_list_rules",
            description = "List all proxy interception rules. Optionally filter by type ('request' or 'response').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("type") { put("type", "string"); put("description", "Filter by rule type ('request' or 'response')") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val typeFilter = args["type"]?.jsonPrimitive?.contentOrNull

                val rules = if (typeFilter != null) {
                    stateManager.proxyRules.filter {
                        it.type.equals(typeFilter, ignoreCase = true)
                    }
                } else {
                    stateManager.proxyRules.toList()
                }

                val result = buildJsonObject {
                    put("total", rules.size)
                    put("rules", buildJsonArray {
                        rules.forEach { rule ->
                            add(serializeProxyRule(rule))
                        }
                    })
                }

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
        // 12. proxy_remove_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_remove_rule",
            description = "Remove a proxy interception rule by its rule ID.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "ID of the rule to remove") }
                },
                required = listOf("rule_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val ruleId = args["rule_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'rule_id' is required")
                        }.toString())),
                        isError = true
                    )

                val removed = stateManager.proxyRules.removeIf { it.ruleId == ruleId }

                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("rule_id", ruleId)
                    put("removed", removed)
                    put("remaining_rules", stateManager.proxyRules.size)
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
        // 13. proxy_auto_auth
        // ---------------------------------------------------------------
        server.addTool(
            name = "proxy_auto_auth",
            description = "Convenience tool: auto-inject an authentication header into all proxy requests matching a host pattern. Creates a proxy request rule that adds the specified header. Use proxy_remove_rule with the returned rule_id to remove it later. Parameters: header_name (default 'Authorization'), header_value (required), host_pattern (regex, default '.*' for all hosts).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("header_name") { put("type", "string"); put("description", "Header name to inject (default 'Authorization')") }
                    putJsonObject("header_value") { put("type", "string"); put("description", "Header value to inject") }
                    putJsonObject("host_pattern") { put("type", "string"); put("description", "Regex host pattern to match (default '.*' for all hosts)") }
                },
                required = listOf("header_value")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val headerName = args["header_name"]?.jsonPrimitive?.contentOrNull ?: "Authorization"
                val headerValue = args["header_value"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'header_value' is required"}""")),
                        isError = true
                    )
                val hostPattern = args["host_pattern"]?.jsonPrimitive?.contentOrNull ?: ".*"

                val ruleId = stateManager.generateId("auto-auth")
                stateManager.proxyRules.add(ProxyRule(
                    ruleId = ruleId,
                    type = "request",
                    matchHost = hostPattern,
                    action = "modify",
                    modifyAddHeader = "$headerName: $headerValue",
                    enabled = true
                ))

                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("rule_id", ruleId)
                    put("status", "active")
                    put("header", "$headerName: $headerValue")
                    put("host_pattern", hostPattern)
                    put("note", "Use proxy_remove_rule with rule_id to deactivate")
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
    }

    // ---------------------------------------------------------------
    // Helper: serialize a ProxyRule to JSON
    // ---------------------------------------------------------------

    private fun serializeProxyRule(rule: ProxyRule): JsonObject {
        return buildJsonObject {
            put("rule_id", rule.ruleId)
            put("type", rule.type)
            put("action", rule.action)
            put("enabled", rule.enabled)
            if (rule.matchHost != null) put("match_host", rule.matchHost)
            if (rule.matchUrl != null) put("match_url", rule.matchUrl)
            if (rule.matchMethod != null) put("match_method", rule.matchMethod)
            if (rule.matchHeader != null) put("match_header", rule.matchHeader)
            if (rule.matchBody != null) put("match_body", rule.matchBody)
            if (rule.matchStatus != null) put("match_status", rule.matchStatus)
            if (rule.modifyAddHeader != null) put("modify_add_header", rule.modifyAddHeader)
            if (rule.modifyRemoveHeader != null) put("modify_remove_header", rule.modifyRemoveHeader)
            if (rule.modifyReplaceHeader != null) {
                put("modify_replace_header", buildJsonObject {
                    rule.modifyReplaceHeader.forEach { (k, v) -> put(k, v) }
                })
            }
            if (rule.modifyBodyRegex != null) put("modify_body_regex", rule.modifyBodyRegex)
            if (rule.modifyBodyReplacement != null) put("modify_body_replacement", rule.modifyBodyReplacement)
            if (rule.tagComment != null) put("tag_comment", rule.tagComment)
            if (rule.tagHighlight != null) put("tag_highlight", rule.tagHighlight)
        }
    }
}
