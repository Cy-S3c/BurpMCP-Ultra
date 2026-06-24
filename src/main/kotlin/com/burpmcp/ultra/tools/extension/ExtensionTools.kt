package com.burpmcp.ultra.tools.extension

import com.burpmcp.ultra.bridge.ExtensionBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ExtensionTools {

    fun register(server: Server, bridge: ExtensionBridge) {

        server.addTool(
            name = "extension_info",
            description = "Get comprehensive information about the BurpMCP-Ultra extension including " +
                "its version, filename, Burp Suite version/edition, MCP server transport ports, " +
                "active runtime state (proxy rules, traffic rules, session rules, scan tasks, " +
                "WebSocket connections, Collaborator clients), and registered handlers " +
                "(scan checks, payload processors). No parameters required.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                val result = bridge.getInfo()
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
