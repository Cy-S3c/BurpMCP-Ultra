package com.burpmcp.ultra.tools.organizer

import com.burpmcp.ultra.bridge.OrganizerBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object OrganizerTools {

    fun register(server: Server, bridge: OrganizerBridge) {

        server.addTool(
            name = "organizer_send",
            description = "Send an HTTP request (and optionally a response) to Burp Suite's " +
                "Organizer tool for bookmarking and note-taking. The Organizer provides a " +
                "persistent store for interesting requests found during testing. Parameters: " +
                "request (raw HTTP request string, required), response (raw HTTP response " +
                "string, optional), host (target hostname, required), port (target port " +
                "number, required), use_tls (boolean, whether to use HTTPS, default false).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port number") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS, default false") }
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
                val response = args["response"]?.jsonPrimitive?.contentOrNull

                val result = bridge.send(rawRequest, response, host, port, useTls)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "organizer_get_items",
            description = "Retrieve items from Burp Suite's Organizer tool. Returns a list " +
                "of bookmarked requests with metadata including URL, method, host, port, " +
                "and response status code. Parameters: url_prefix (optional string, filter " +
                "items whose URL contains this prefix), max_results (optional integer, " +
                "maximum number of items to return, default 100).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url_prefix") { put("type", "string"); put("description", "Filter items whose URL contains this prefix") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum number of items to return, default 100") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val urlPrefix = args["url_prefix"]?.jsonPrimitive?.contentOrNull
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 100

                val result = bridge.getItems(urlPrefix, maxResults)
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
