package com.burpmcp.ultra.tools.sitemap

import com.burpmcp.ultra.bridge.SitemapBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object SitemapTools {

    fun register(server: Server, bridge: SitemapBridge) {

        server.addTool(
            name = "sitemap_query",
            description = "Query the Burp Suite site map for HTTP request/response entries. " +
                "Supports filtering by URL prefix and regex search pattern. Parameters: " +
                "url_prefix (optional, filter entries whose URL starts with this prefix), " +
                "search_pattern (optional, regex pattern to match against URLs), " +
                "max_results (optional, maximum entries to return, default 100), " +
                "include_request (optional, boolean, include full request text, default false), " +
                "include_response (optional, boolean, include full response text, default false).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "Filter entries whose URL starts with this prefix") }
                    putJsonObject("search_pattern") { put("type", "string"); put("description", "Regex pattern to match against URLs") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum entries to return, default 100") }
                    putJsonObject("include_request") { put("type", "boolean"); put("description", "Include full request text, default false") }
                    putJsonObject("include_response") { put("type", "boolean"); put("description", "Include full response text, default false") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val searchPattern = args["search_pattern"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 100
                val includeRequest = args["include_request"]?.jsonPrimitive?.booleanOrNull ?: false
                val includeResponse = args["include_response"]?.jsonPrimitive?.booleanOrNull ?: false

                val result = bridge.query(urlPrefix, searchPattern, maxResults, includeRequest, includeResponse)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "sitemap_get_issues",
            description = "Retrieve audit issues from the Burp Suite site map. Returns scanner-reported " +
                "vulnerabilities with severity, confidence, and affected URLs. Parameters: " +
                "url_prefix (optional, filter issues by URL prefix), severity (optional, " +
                "filter by severity: HIGH, MEDIUM, LOW, INFORMATION).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "Filter issues by URL prefix") }
                    putJsonObject("severity") { put("type", "string"); put("description", "Filter by severity: HIGH, MEDIUM, LOW, INFORMATION") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val severity = args["severity"]?.jsonPrimitive?.contentOrNull

                val result = bridge.getIssues(urlPrefix, severity)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "sitemap_add_request",
            description = "Add an HTTP request (and optional response) to the Burp Suite site map. " +
                "This allows programmatic population of the site map with discovered endpoints. " +
                "Parameters: request (raw HTTP request string), response (optional, raw HTTP " +
                "response string), host (target hostname), port (target port), use_tls (boolean).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use TLS, default false") }
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
                val rawResponse = args["response"]?.jsonPrimitive?.contentOrNull
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

                val result = bridge.addRequest(rawRequest, rawResponse, host, port, useTls)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "sitemap_add_issue",
            description = "Add a custom audit issue to the Burp Suite site map. Used to report " +
                "custom-discovered vulnerabilities alongside Burp's built-in scanner findings. " +
                "Parameters: name (issue title), detail (HTML description of the issue), " +
                "remediation (optional, HTML remediation advice), severity (HIGH, MEDIUM, LOW, " +
                "or INFORMATION), confidence (CERTAIN, FIRM, or TENTATIVE), url (affected URL), " +
                "request (optional, raw HTTP request demonstrating the issue), response (optional, " +
                "raw HTTP response demonstrating the issue).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Issue title") }
                    putJsonObject("detail") { put("type", "string"); put("description", "HTML description of the issue") }
                    putJsonObject("remediation") { put("type", "string"); put("description", "HTML remediation advice") }
                    putJsonObject("severity") { put("type", "string"); put("description", "Severity: HIGH, MEDIUM, LOW, or INFORMATION") }
                    putJsonObject("confidence") { put("type", "string"); put("description", "Confidence: CERTAIN, FIRM, or TENTATIVE") }
                    putJsonObject("url") { put("type", "string"); put("description", "Affected URL") }
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request demonstrating the issue") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response demonstrating the issue") }
                },
                required = listOf("name", "detail", "severity", "confidence", "url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args["name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: name"}""")),
                        isError = true
                    )
                val detail = args["detail"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: detail"}""")),
                        isError = true
                    )
                val remediation = args["remediation"]?.jsonPrimitive?.contentOrNull
                val severity = args["severity"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: severity"}""")),
                        isError = true
                    )
                val confidence = args["confidence"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: confidence"}""")),
                        isError = true
                    )
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: url"}""")),
                        isError = true
                    )
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                val rawResponse = args["response"]?.jsonPrimitive?.contentOrNull

                val result = bridge.addIssue(name, detail, remediation, severity, confidence, url, rawRequest, rawResponse)
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
