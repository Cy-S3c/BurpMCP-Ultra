package com.burpmcp.ultra.tools.project

import com.burpmcp.ultra.bridge.ProjectBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ProjectTools {

    fun register(server: Server, bridge: ProjectBridge) {

        server.addTool(
            name = "project_info",
            description = "Get information about the current Burp Suite project including its " +
                "name, unique identifier, and description. No parameters required.",
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
