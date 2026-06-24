package com.burpmcp.ultra.tools.repeater

import com.burpmcp.ultra.bridge.RepeaterBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object RepeaterTools {

    fun register(server: Server, bridge: RepeaterBridge) {
        server.addTool(
            name = "repeater_send",
            description = "Send an HTTP request to Burp Suite's Repeater tool. " +
                "Creates a new Repeater tab with the specified request, allowing manual " +
                "replay and modification. Parameters: request (raw HTTP request string), " +
                "host (target hostname), port (target port number), use_tls (boolean, " +
                "whether to use HTTPS), tab_name (optional, name for the Repeater tab).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port number") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS)") }
                    putJsonObject("tab_name") { put("type", "string"); put("description", "Optional name for the Repeater tab") }
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
                val tabName = args["tab_name"]?.jsonPrimitive?.contentOrNull

                val result = bridge.sendToRepeater(rawRequest, host, port, useTls, tabName)
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
