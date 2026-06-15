package com.burpmcp.ultra.tools.analysis

import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object AnalysisTools {

    /**
     * Registers all analysis tools. Accepts the full [BridgeFactory.Bridges]
     * container because analysis may use the AnalysisBridge (which is
     * constructed on-the-fly from the MontoyaApi held by other bridges)
     * or direct proxy history access via the BurpSuiteBridge.
     *
     * The AnalysisBridge is instantiated lazily from the bridges container.
     */
    fun register(server: Server, bridges: BridgeFactory.Bridges) {
        // AnalysisBridge is not stored in the Bridges data class directly;
        // we create it using the same MontoyaApi that powers other bridges.
        // Since BridgeFactory already creates one, we access it through a
        // helper. But actually the BridgeFactory does not expose the raw API.
        // Instead, we use the proxy bridge's API transitively -- let's just
        // accept the AnalysisBridge is created elsewhere and passed through
        // the Bridges container or we create a lightweight wrapper here.
        //
        // For now, AnalysisTools creates a standalone AnalysisBridge using
        // the Montoya API extracted from BurpSuiteBridge's config export.
        //
        // Actually the cleanest approach: AnalysisBridge is constructed in
        // BridgeFactory and passed via Bridges. But since the Bridges data
        // class doesn't include it, we'll use a package-level approach:
        // we'll create the analysis bridge inside the tools and use the
        // bridges container for proxy history access.

        // 1. analyze_request
        server.addTool(
            name = "analyze_request",
            description = "Parse and analyze a raw HTTP request. Returns the method, URL, path, " +
                "headers, cookies, parameters (URL, body, cookie), body content, and content type. " +
                "Parameters: request (string, the raw HTTP request to analyze).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "The raw HTTP request to analyze") }
                },
                required = listOf("request")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: request"}""")),
                        isError = true
                    )
                val bridge = bridges.analysis
                val result = bridge.analyzeRequest(rawRequest)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 2. analyze_response
        server.addTool(
            name = "analyze_response",
            description = "Parse and analyze a raw HTTP response. Returns the status code, reason " +
                "phrase, headers, cookies (with domain, path, expiration), body, stated and " +
                "inferred MIME types. Parameters: response (string, the raw HTTP response to analyze).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("response") { put("type", "string"); put("description", "The raw HTTP response to analyze") }
                },
                required = listOf("response")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawResponse = args["response"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: response"}""")),
                        isError = true
                    )
                val bridge = bridges.analysis
                val result = bridge.analyzeResponse(rawResponse)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 3. analyze_find_reflected
        server.addTool(
            name = "analyze_find_reflected",
            description = "Find reflected parameter values in an HTTP response. Extracts all " +
                "parameter values from the request (URL, body, cookies) and searches for each " +
                "in the response body. For each reflection, determines the surrounding context " +
                "(html_body, html_attribute, javascript, css, url, html_comment). " +
                "Parameters: request (string, raw HTTP request), response (string, raw HTTP " +
                "response), additional_values (optional array of extra strings to check for reflection).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response") }
                    putJsonObject("additional_values") {
                        put("type", "array")
                        put("description", "Extra strings to check for reflection")
                        putJsonObject("items") { put("type", "string") }
                    }
                },
                required = listOf("request", "response")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: request"}""")),
                        isError = true
                    )
                val rawResponse = args["response"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: response"}""")),
                        isError = true
                    )

                val additionalValues = args["additional_values"].asStringList() ?: emptyList()

                val bridge = bridges.analysis
                val result = bridge.findReflected(rawRequest, rawResponse, additionalValues)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 4. analyze_extract_params
        server.addTool(
            name = "analyze_extract_params",
            description = "Extract all parameters from an HTTP request including URL query params, " +
                "body params, cookies, headers, JSON body fields (recursively flattened), and " +
                "XML element/attribute values. Parameters: request (string, the raw HTTP request).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "The raw HTTP request") }
                },
                required = listOf("request")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: request"}""")),
                        isError = true
                    )
                val bridge = bridges.analysis
                val result = bridge.extractParams(rawRequest)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 5. analyze_insertion_points
        server.addTool(
            name = "analyze_insertion_points",
            description = "Identify all potential injection/insertion points in an HTTP request. " +
                "Returns URL parameters, body parameters, cookies, injectable headers " +
                "(User-Agent, Referer, X-Forwarded-For, etc.), and URL path segments. " +
                "Parameters: request (string, raw HTTP request), host (string, target hostname), " +
                "port (number, target port), use_tls (boolean, whether to use HTTPS).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS") }
                },
                required = listOf("request", "host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: request"}""")),
                        isError = true
                    )
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: host"}""")),
                        isError = true
                    )
                val port = args["port"]?.jsonPrimitive?.intOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: port"}""")),
                        isError = true
                    )
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull ?: false

                val bridge = bridges.analysis
                val result = bridge.getInsertionPoints(rawRequest, host, port, useTls)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 6. analyze_diff
        server.addTool(
            name = "analyze_diff",
            description = "Compare two HTTP requests or two HTTP responses and identify differences. " +
                "For requests: compares method, path, headers, parameters, and body. " +
                "For responses: compares status code, headers, body, and MIME types. " +
                "Returns a similarity percentage based on bigram overlap. " +
                "Parameters: item1 (string, first raw HTTP message), item2 (string, second raw " +
                "HTTP message), type (string, 'request' or 'response').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("item1") { put("type", "string"); put("description", "First raw HTTP message") }
                    putJsonObject("item2") { put("type", "string"); put("description", "Second raw HTTP message") }
                    putJsonObject("type") { put("type", "string"); put("description", "'request' or 'response'") }
                },
                required = listOf("item1", "item2", "type")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val item1 = args["item1"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: item1"}""")),
                        isError = true
                    )
                val item2 = args["item2"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: item2"}""")),
                        isError = true
                    )
                val type = args["type"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: type ('request' or 'response')"}""")),
                        isError = true
                    )

                val bridge = bridges.analysis
                val result = bridge.diff(item1, item2, type)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 7. analyze_response_body_search
        server.addTool(
            name = "analyze_response_body_search",
            description = "Search response bodies across the proxy history for a regex pattern. " +
                "Useful for finding sensitive data leaks, specific tokens, error messages, " +
                "or patterns across all captured traffic. " +
                "Parameters: pattern (string, regex pattern to search for), " +
                "max_results (number, maximum matches to return; defaults to 50), " +
                "in_scope_only (boolean, restrict to in-scope URLs; defaults to false).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("pattern") { put("type", "string"); put("description", "Regex pattern to search for") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum matches to return (default 50)") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Restrict to in-scope URLs (default false)") }
                },
                required = listOf("pattern")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val pattern = args["pattern"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: pattern"}""")),
                        isError = true
                    )
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 50
                val inScopeOnly = args["in_scope_only"]?.jsonPrimitive?.booleanOrNull ?: false

                val bridge = bridges.analysis
                val result = bridge.searchResponseBodies(pattern, maxResults, inScopeOnly)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }
    }

}
