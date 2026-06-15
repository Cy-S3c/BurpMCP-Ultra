package com.burpmcp.ultra.tools.authdiff

import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.core.asJsonObjectList
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object AuthDiffTools {
    fun register(server: Server, bridges: BridgeFactory.Bridges) {
        server.addTool(
            name = "auth_diff",
            description = """Authorization level diffing: sends the same request with different auth levels (admin, user, unauthenticated) and compares responses to detect IDOR, privilege escalation, and broken access control.

Provide auth_levels as an array of objects: [{"name": "admin", "header_name": "Authorization", "header_value": "Bearer admin-token"}, {"name": "user", "header_name": "Authorization", "header_value": "Bearer user-token"}, {"name": "none"}]

The tool automatically strips auth headers for "none"/"unauth" levels. Analyzes status codes, body content, body length, and headers for differences. Flags critical findings like identical responses across auth levels.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port number (default 443)") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("auth_levels") { put("type", "array"); putJsonObject("items") { put("type", "object") }; put("description", "Array of auth level objects (name, header_name, header_value)") }
                    putJsonObject("compare_fields") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Optional list of response fields to compare") }
                },
                required = listOf("request", "host", "auth_levels")
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
                    ?: (port == 443)
                val authLevels = args["auth_levels"].asJsonObjectList()
                    ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'auth_levels' is required (array of auth level objects)"}""")), isError = true)
                val compareFields = args["compare_fields"].asStringList()

                val result = bridges.analysis.authDiff(reqStr, host, port, useTls, authLevels, compareFields)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(content = listOf(TextContent("""{"error":"${e.message}"}""")), isError = true)
            }
        }
    }
}
