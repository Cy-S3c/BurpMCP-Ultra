package com.burpmcp.ultra.tools.http

import com.burpmcp.ultra.bridge.HttpBridge
import com.burpmcp.ultra.core.asStringList
import com.burpmcp.ultra.core.asStringMap
import com.burpmcp.ultra.core.asStringMapResult
import com.burpmcp.ultra.core.asJsonObjectList
import com.burpmcp.ultra.core.asBodyString
import com.burpmcp.ultra.core.asLongSafe
import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.state.TrafficRule
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers all 13 HTTP MCP tools onto the given [Server].
 *
 * Each tool delegates to the [HttpBridge] and catches exceptions so
 * that errors are returned as structured JSON inside a [CallToolResult]
 * rather than propagating unhandled.
 */
object HttpTools {

    /**
     * Default per-request timeout when caller does not pass timeout_ms. Prevents agents
     * from hanging indefinitely on unresponsive targets or stuck SSE streams. Override
     * with the BURPMCP_DEFAULT_TIMEOUT_MS env var at extension load time.
     */
    private val DEFAULT_TIMEOUT_MS: Long =
        System.getenv("BURPMCP_DEFAULT_TIMEOUT_MS")?.toLongOrNull() ?: 30_000L

    fun register(server: Server, bridge: HttpBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. http_send_request
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_request",
            description = """Send an HTTP request through Burp Suite. Build from URL + method + headers + body, or from a raw HTTP request string. Supports HTTP/1.1, HTTP/2, and connection reuse.

Parameters:
- url (string): target URL (use this OR raw_request)
- method (string): HTTP method (default GET)
- headers (object): map of header name → value. Caller-supplied headers are preserved byte-exact (Burp's default User-Agent/Accept etc. are NOT injected when headers are provided).
- body (string OR object/array): request body. If object/array, it is serialized to compact JSON automatically.
- raw_request (string): raw HTTP request text. When supplied without explicit port/use_tls, defaults to TLS:443 (modern web default). Content-Length is auto-recomputed if it does not match body bytes.
- host, port (int), use_tls (bool): explicit service overrides
- http_mode (string): "AUTO" | "HTTP_1" | "HTTP_2" | "HTTP_2_IGNORE_ALPN"
- connection_id (string): reuse a prior connection
- max_response_length (int): truncate response body in result
- timeout_ms (number): hard timeout. Returns is_timeout=true on expiry.
- preserve_headers (bool, default true): when false, falls back to Burp's httpRequestFromUrl which adds default headers
- auto_fix_content_length (bool, default true): when false, uses raw_request CL as-is

Returns full response with headers, body, status code, and timing.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL (use this OR raw_request)") }
                    putJsonObject("method") { put("type", "string"); put("description", "HTTP method (default GET)") }
                    putJsonObject("headers") { put("type", "object"); put("description", "Map of header name to value") }
                    putJsonObject("body") { put("type", "string"); put("description", "Request body (string, or object/array serialized to JSON)") }
                    putJsonObject("raw_request") { put("type", "string"); put("description", "Raw HTTP request text") }
                    putJsonObject("host") { put("type", "string"); put("description", "Explicit target hostname override") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Explicit target port override") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("http_mode") { put("type", "string"); put("description", "AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN") }
                    putJsonObject("connection_id") { put("type", "string"); put("description", "Reuse a prior connection") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response body in result") }
                    putJsonObject("timeout_ms") { put("type", "number"); put("description", "Hard timeout in milliseconds") }
                    putJsonObject("preserve_headers") { put("type", "boolean"); put("description", "Preserve caller headers byte-exact (default true)") }
                    putJsonObject("auto_fix_content_length") { put("type", "boolean"); put("description", "Recompute Content-Length to match body (default true)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val url = args["url"]?.jsonPrimitive?.contentOrNull
                val method = args["method"]?.jsonPrimitive?.contentOrNull
                val body = args["body"].asBodyString()
                val rawRequest = args["raw_request"]?.jsonPrimitive?.contentOrNull
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                val port = args["port"]?.jsonPrimitive?.intOrNull
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull
                val httpMode = args["http_mode"]?.jsonPrimitive?.contentOrNull
                val connectionId = args["connection_id"]?.jsonPrimitive?.contentOrNull
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull
                val timeoutMs = args["timeout_ms"].asLongSafe() ?: DEFAULT_TIMEOUT_MS
                val preserveHeaders = args["preserve_headers"]?.jsonPrimitive?.booleanOrNull ?: true
                val autoFixContentLength = args["auto_fix_content_length"]?.jsonPrimitive?.booleanOrNull ?: true

                if (url == null && rawRequest == null) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Either 'url' or 'raw_request' must be provided")
                        }.toString())),
                        isError = true
                    )
                }

                // Headers parsing — accepts object, array-of-pairs, array-of-{name,value}, raw header block.
                // Surfaces a warning back to the caller when the input format is unusual or partly bad,
                // instead of silently dropping headers (the previous bug).
                val headersInput = args["headers"]
                val (headers, headersWarning) = headersInput.asStringMapResult()
                val headersDropped = headersInput != null && headersInput !is JsonNull && headers == null

                val result = bridge.sendRequest(
                    url, method, headers, body, rawRequest, host, port, useTls,
                    httpMode, connectionId, maxResponseLength,
                    timeoutMs, preserveHeaders, autoFixContentLength
                )

                // Augment result with header diagnostics if applicable.
                val augmented = if (headersWarning != null || headersDropped) {
                    buildJsonObject {
                        result.forEach { (k, v) -> put(k, v) }
                        if (headersWarning != null) put("headers_warning", headersWarning)
                        if (headersDropped) put(
                            "headers_dropped",
                            "Provided 'headers' could not be parsed and were NOT applied. Use {\"X-Foo\":\"bar\"} or [[\"X-Foo\",\"bar\"]]."
                        )
                    }
                } else result

                CallToolResult(content = listOf(TextContent(augmented.toString())))
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
        // 2. http_send_requests_parallel
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_requests_parallel",
            description = """Send multiple HTTP requests in parallel through Burp Suite. Each request in the array can specify url, method, headers, body (string or object), or raw_request.

Mixed hosts are supported: requests are grouped by HTTP service (host+port+tls) and dispatched per-group, then merged back into the original input order. Per-group dispatch failures do not abort the batch — failed slots come back with error/phase fields.

Parameters:
- requests (array, required): per-request objects with the same fields as http_send_request
- http_mode (string): "AUTO" | "HTTP_1" | "HTTP_2" | "HTTP_2_IGNORE_ALPN"
- max_response_length (int): truncate response bodies
- timeout_ms (number): hard timeout for the entire batch

Returns array of results in original order, plus group_timings_ms and groups_dispatched.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("requests") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "Per-request objects with the same fields as http_send_request") }
                    putJsonObject("http_mode") { put("type", "string"); put("description", "AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response bodies") }
                    putJsonObject("timeout_ms") { put("type", "number"); put("description", "Hard timeout for the entire batch in milliseconds") }
                },
                required = listOf("requests")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val requests = args["requests"].asJsonObjectList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'requests' is required (array of request objects)")
                        }.toString())),
                        isError = true
                    )

                val httpMode = args["http_mode"]?.jsonPrimitive?.contentOrNull
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull
                val timeoutMs = args["timeout_ms"].asLongSafe() ?: DEFAULT_TIMEOUT_MS

                val result = bridge.sendRequestsParallel(requests, httpMode, maxResponseLength, timeoutMs)
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
        // 3. http_send_request_chain
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_request_chain",
            description = "Send a chain of HTTP requests sequentially with variable extraction between steps. Each step can extract values from the response using regex (capture groups) and inject them into subsequent steps via {{variable}} placeholders. Useful for CSRF tokens, session tokens, and multi-step workflows.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("steps") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "Array of step objects with url/raw_request and optional extract definitions") }
                    putJsonObject("http_mode") { put("type", "string"); put("description", "AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN") }
                    putJsonObject("stop_on_error") { put("type", "boolean"); put("description", "Stop the chain on the first error (default true)") }
                },
                required = listOf("steps")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val steps = args["steps"].asJsonObjectList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'steps' is required (array of step objects with url/raw_request and optional extract definitions)")
                        }.toString())),
                        isError = true
                    )

                val httpMode = args["http_mode"]?.jsonPrimitive?.contentOrNull
                val stopOnError = args["stop_on_error"]?.jsonPrimitive?.booleanOrNull ?: true

                val result = bridge.sendRequestChain(steps, httpMode, stopOnError)
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
        // 4. http_cookie_jar_get
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_cookie_jar_get",
            description = "Get cookies from Burp Suite's cookie jar. Optionally filter by domain substring.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("domain") { put("type", "string"); put("description", "Optional domain substring filter") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val domain = args["domain"]?.jsonPrimitive?.contentOrNull

                val result = bridge.getCookieJar(domain)
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
        // 5. http_cookie_jar_set
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_cookie_jar_set",
            description = "Set a cookie in Burp Suite's cookie jar.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Cookie name") }
                    putJsonObject("value") { put("type", "string"); put("description", "Cookie value") }
                    putJsonObject("domain") { put("type", "string"); put("description", "Cookie domain") }
                    putJsonObject("path") { put("type", "string"); put("description", "Cookie path (default /)") }
                    putJsonObject("expiration") { put("type", "string"); put("description", "Optional cookie expiration") }
                },
                required = listOf("name", "value", "domain")
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
                val value = args["value"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'value' is required")
                        }.toString())),
                        isError = true
                    )
                val domain = args["domain"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'domain' is required")
                        }.toString())),
                        isError = true
                    )

                val path = args["path"]?.jsonPrimitive?.contentOrNull ?: "/"
                val expiration = args["expiration"]?.jsonPrimitive?.contentOrNull

                val result = bridge.setCookie(name, value, domain, path, expiration)
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
        // 6. http_analyze_keywords
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_analyze_keywords",
            description = "Analyze an HTTP response for keyword occurrences using Burp's built-in keyword analysis engine. Useful for identifying which keywords vary across multiple responses (e.g., during content discovery).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response string") }
                    putJsonObject("keywords") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Array of keyword strings") }
                    putJsonObject("case_sensitive") { put("type", "boolean"); put("description", "Whether matching is case-sensitive (default false)") }
                },
                required = listOf("response", "keywords")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val response = args["response"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'response' is required (raw HTTP response string)")
                        }.toString())),
                        isError = true
                    )

                val keywords = args["keywords"].asStringList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'keywords' is required (array of keyword strings)")
                        }.toString())),
                        isError = true
                    )

                val caseSensitive = args["case_sensitive"]?.jsonPrimitive?.booleanOrNull ?: false

                val result = bridge.analyzeKeywords(response, keywords, caseSensitive)
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
        // 7. http_analyze_variations
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_analyze_variations",
            description = "Analyze variations across multiple HTTP responses. Identifies which response attributes (status code, content length, headers, body content, etc.) vary and which are invariant. Useful for identifying valid vs. invalid responses in fuzzing/scanning.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("responses") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Array of raw HTTP response strings (at least 2)") }
                },
                required = listOf("responses")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val responses = args["responses"].asStringList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'responses' is required (array of raw HTTP response strings)")
                        }.toString())),
                        isError = true
                    )

                if (responses.size < 2) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "At least 2 responses are required for variation analysis")
                        }.toString())),
                        isError = true
                    )
                }

                val result = bridge.analyzeVariations(responses)
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
        // 8. http_set_traffic_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_set_traffic_rule",
            description = "Register a global HTTP traffic modification rule. Rules apply to all HTTP traffic (not just proxy) and can add, remove, or replace headers on matching requests or responses. If rule_id matches an existing rule, it is replaced.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Rule ID; if it matches an existing rule it is replaced (auto-generated if omitted)") }
                    putJsonObject("direction") { put("type", "string"); put("description", "'request' or 'response'") }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Match on request URL") }
                    putJsonObject("match_host") { put("type", "string"); put("description", "Match on host") }
                    putJsonObject("match_header") { put("type", "string"); put("description", "Match on header") }
                    putJsonObject("modify_add_header") { put("type", "string"); put("description", "Header to add") }
                    putJsonObject("modify_remove_header") { put("type", "string"); put("description", "Header to remove") }
                    putJsonObject("modify_replace_header") { put("type", "object"); put("description", "Map of header name to replacement value") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("direction")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val ruleId = args["rule_id"]?.jsonPrimitive?.contentOrNull
                    ?: stateManager.generateId("trule")

                val direction = args["direction"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'direction' is required ('request' or 'response')")
                        }.toString())),
                        isError = true
                    )

                if (!direction.equals("request", ignoreCase = true) &&
                    !direction.equals("response", ignoreCase = true)
                ) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'direction' must be 'request' or 'response'")
                        }.toString())),
                        isError = true
                    )
                }

                val replaceHeader = args["modify_replace_header"]?.jsonObject?.let { obj ->
                    obj.entries.associate { (k, v) -> k to v.jsonPrimitive.content }
                }

                val rule = TrafficRule(
                    ruleId = ruleId,
                    direction = direction.lowercase(),
                    matchUrl = args["match_url"]?.jsonPrimitive?.contentOrNull,
                    matchHost = args["match_host"]?.jsonPrimitive?.contentOrNull,
                    matchHeader = args["match_header"]?.jsonPrimitive?.contentOrNull,
                    modifyAddHeader = args["modify_add_header"]?.jsonPrimitive?.contentOrNull,
                    modifyRemoveHeader = args["modify_remove_header"]?.jsonPrimitive?.contentOrNull,
                    modifyReplaceHeader = replaceHeader,
                    enabled = args["enabled"]?.jsonPrimitive?.booleanOrNull ?: true
                )

                // Remove existing rule with same ID, then add the new one
                stateManager.trafficRules.removeIf { it.ruleId == ruleId }
                stateManager.trafficRules.add(rule)

                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("rule_set", true)
                    put("rule_id", ruleId)
                    put("direction", direction.lowercase())
                    put("total_rules", stateManager.trafficRules.size)
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
        // 9. http_list_traffic_rules
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_list_traffic_rules",
            description = "List all registered global HTTP traffic modification rules.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val rules = stateManager.trafficRules.toList()

                val result = buildJsonObject {
                    put("total", rules.size)
                    put("rules", buildJsonArray {
                        rules.forEach { rule ->
                            add(serializeTrafficRule(rule))
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
        // 10. http_remove_traffic_rule
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_remove_traffic_rule",
            description = "Remove a global HTTP traffic modification rule by its rule ID.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "The rule ID to remove") }
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

                val removed = stateManager.trafficRules.removeIf { it.ruleId == ruleId }

                CallToolResult(content = listOf(TextContent(buildJsonObject {
                    put("rule_id", ruleId)
                    put("removed", removed)
                    put("remaining_rules", stateManager.trafficRules.size)
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
        // 11. http_send_raw_bytes
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_send_raw_bytes",
            description = "Send a raw byte-level HTTP request for HTTP request smuggling and CRLF injection testing. Accepts either hex-encoded bytes (raw_request_hex) or a string with literal \\r\\n sequences (raw_request). Preserves exact byte sequences without normalization. Requires host, port, and use_tls parameters.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("raw_request_hex") { put("type", "string"); put("description", "Hex-encoded request bytes (use this OR raw_request)") }
                    putJsonObject("raw_request") { put("type", "string"); put("description", "Request string with literal \\r\\n sequences") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port number (default 443)") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("tls") { put("type", "boolean"); put("description", "Alias for use_tls") }
                    putJsonObject("https") { put("type", "boolean"); put("description", "Alias for use_tls") }
                    putJsonObject("http_mode") { put("type", "string"); put("description", "AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response body in result") }
                    putJsonObject("timeout_ms") { put("type", "number"); put("description", "Hard timeout in milliseconds") }
                },
                required = listOf("host")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val rawHex = args["raw_request_hex"]?.jsonPrimitive?.contentOrNull
                val rawString = args["raw_request"]?.jsonPrimitive?.contentOrNull
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'host' is required"}""")),
                        isError = true
                    )
                val port = args["port"]?.jsonPrimitive?.intOrNull ?: 443
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["https"]?.jsonPrimitive?.booleanOrNull
                    ?: (port == 443)
                val httpMode = args["http_mode"]?.jsonPrimitive?.contentOrNull
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull
                val timeoutMs = args["timeout_ms"].asLongSafe() ?: DEFAULT_TIMEOUT_MS

                if (rawHex == null && rawString == null) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Either 'raw_request_hex' or 'raw_request' must be provided"}""")),
                        isError = true
                    )
                }

                val result = bridge.sendRawBytes(rawHex, rawString, host, port, useTls, httpMode, maxResponseLength, timeoutMs)
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
        // 12. http_fuzz
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_fuzz",
            description = """Fuzz an HTTP request by injecting payloads at marked positions (sniper mode). Three position modes supported:

1. FUZZ keyword (easiest): Put FUZZ where you want payloads injected. Example: GET /api?id=FUZZ HTTP/1.1\r\nHost: target.com\r\n\r\n
2. Marker pairs (like Burp Intruder): Wrap values with § markers. Example: GET /api?id=§1§&name=§test§ HTTP/1.1\r\n... Each §value§ pair is an injection point.
3. Offset pairs (legacy): Provide positions array of [start, end] byte offsets.

Use \r\n for line endings in the request string. Returns all responses with payload metadata.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Request string with FUZZ keyword or § markers") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port number (default 443)") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("tls") { put("type", "boolean"); put("description", "Alias for use_tls") }
                    putJsonObject("https") { put("type", "boolean"); put("description", "Alias for use_tls") }
                    putJsonObject("http_mode") { put("type", "string"); put("description", "AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response bodies") }
                    putJsonObject("marker") { put("type", "string"); put("description", "Custom injection marker") }
                    putJsonObject("positions") { put("type", "array"); putJsonObject("items") { put("type", "array") }; put("description", "Optional [start, end] byte offset pairs") }
                    putJsonObject("payloads") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Array of payload strings") }
                    putJsonObject("payload_library") { put("type", "string"); put("description", "Built-in payload set merged with 'payloads': xss | sqli | traversal | ssti | cmdi") }
                },
                required = listOf("request", "host")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val reqStr = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'request' is required"}""")),
                        isError = true
                    )
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'host' is required"}""")),
                        isError = true
                    )
                val port = args["port"]?.jsonPrimitive?.intOrNull ?: 443
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["https"]?.jsonPrimitive?.booleanOrNull
                    ?: (port == 443)
                val httpMode = args["http_mode"]?.jsonPrimitive?.contentOrNull
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull
                val marker = args["marker"]?.jsonPrimitive?.contentOrNull

                // Positions are optional now — FUZZ keyword and §marker§ modes auto-detect
                val positions = args["positions"]?.let { posEl ->
                    try {
                        posEl.jsonArray.map { p ->
                            val arr = p.jsonArray
                            Pair(arr[0].jsonPrimitive.int, arr[1].jsonPrimitive.int)
                        }
                    } catch (_: Exception) { null }
                }

                val library = args["payload_library"]?.jsonPrimitive?.contentOrNull
                val libPayloads = library?.let { com.burpmcp.ultra.core.PayloadLibraries.get(it) }
                if (library != null && libPayloads == null) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Unknown payload_library '$library'. Available: ${com.burpmcp.ultra.core.PayloadLibraries.names().joinToString(", ")}")
                        }.toString())),
                        isError = true
                    )
                }
                val payloads = (args["payloads"].asStringList() ?: emptyList()) + (libPayloads ?: emptyList())
                if (payloads.isEmpty()) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Provide 'payloads' (array) and/or 'payload_library' (xss|sqli|traversal|ssti|cmdi)"}""")),
                        isError = true
                    )
                }

                val result = bridge.fuzz(reqStr, host, port, useTls, positions, payloads, httpMode, maxResponseLength, marker)
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
        // 13. http_race
        // ---------------------------------------------------------------
        server.addTool(
            name = "http_race",
            description = """Race condition tester: dispatches N requests concurrently via Burp's parallel request engine for TOCTOU, double-spend, and limit bypass detection. Analyzes response variations (status codes, body lengths) to surface likely race conditions. Use the FUZZ keyword with 'payloads' for varied requests (payloads takes precedence over 'count'). NOTE: best-effort concurrency, NOT guaranteed single-packet/last-byte synchronization.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Request string (use FUZZ keyword for varied payloads)") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port number (default 443)") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("tls") { put("type", "boolean"); put("description", "Alias for use_tls") }
                    putJsonObject("https") { put("type", "boolean"); put("description", "Alias for use_tls") }
                    putJsonObject("count") { put("type", "integer"); put("description", "Number of simultaneous requests (default 10)") }
                    putJsonObject("payloads") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Optional payloads for FUZZ keyword") }
                    putJsonObject("http_mode") { put("type", "string"); put("description", "AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN") }
                    putJsonObject("max_response_length") { put("type", "integer"); put("description", "Truncate response bodies") }
                    putJsonObject("gate_delay") { put("type", "integer"); put("description", "Milliseconds to sleep before dispatching the batch (pre-dispatch gate). 0 dispatches immediately (default 100)") }
                },
                required = listOf("request", "host")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val reqStr = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'request' is required"}""")), isError = true)
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'host' is required"}""")), isError = true)
                val port = args["port"]?.jsonPrimitive?.intOrNull ?: 443
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["tls"]?.jsonPrimitive?.booleanOrNull
                    ?: args["https"]?.jsonPrimitive?.booleanOrNull
                    ?: (port == 443)
                val count = args["count"]?.jsonPrimitive?.intOrNull ?: 10
                val payloads = args["payloads"].asStringList()
                val httpMode = args["http_mode"]?.jsonPrimitive?.contentOrNull
                val maxResponseLength = args["max_response_length"]?.jsonPrimitive?.intOrNull
                val gateDelay = args["gate_delay"]?.jsonPrimitive?.longOrNull ?: 100L

                val result = bridge.raceCondition(reqStr, host, port, useTls, count, payloads, httpMode, maxResponseLength, gateDelay)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(content = listOf(TextContent("""{"error":"${e.message}"}""")), isError = true)
            }
        }
    }

    // ---------------------------------------------------------------
    // Helper: serialize a TrafficRule to JSON
    // ---------------------------------------------------------------

    private fun serializeTrafficRule(rule: TrafficRule): JsonObject {
        return buildJsonObject {
            put("rule_id", rule.ruleId)
            put("direction", rule.direction)
            put("enabled", rule.enabled)
            if (rule.matchUrl != null) put("match_url", rule.matchUrl)
            if (rule.matchHost != null) put("match_host", rule.matchHost)
            if (rule.matchHeader != null) put("match_header", rule.matchHeader)
            if (rule.modifyAddHeader != null) put("modify_add_header", rule.modifyAddHeader)
            if (rule.modifyRemoveHeader != null) put("modify_remove_header", rule.modifyRemoveHeader)
            if (rule.modifyReplaceHeader != null) {
                put("modify_replace_header", buildJsonObject {
                    rule.modifyReplaceHeader.forEach { (k, v) -> put(k, v) }
                })
            }
        }
    }
}
