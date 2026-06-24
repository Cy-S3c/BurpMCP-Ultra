package com.burpmcp.ultra.tools.ai

import com.burpmcp.ultra.bridge.AiBridge
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object AiTools {

    fun register(server: Server, bridge: AiBridge) {

        // 1. ai_status
        server.addTool(
            name = "ai_status",
            description = "Check whether Burp Suite's AI feature is enabled and " +
                "available. Returns the current AI status. This feature is only " +
                "available in Burp Suite Professional 2025+ editions.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { request ->
            try {
                val result = bridge.isEnabled()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 2. ai_prompt
        server.addTool(
            name = "ai_prompt",
            description = "Send a prompt to Burp Suite's built-in AI and receive a " +
                "response. Useful for security analysis, vulnerability explanation, " +
                "and remediation advice. Parameters: messages (required, array of " +
                "strings forming the prompt), context (optional string providing " +
                "additional background context for the AI). Requires Burp Suite " +
                "Professional with AI enabled.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("messages") {
                        put("type", "array")
                        put("description", "Array of strings forming the prompt")
                        putJsonObject("items") { put("type", "string") }
                    }
                    putJsonObject("context") { put("type", "string"); put("description", "Additional background context for the AI") }
                },
                required = listOf("messages")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val messages = args["messages"].asStringList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: messages (array of strings)"}""")),
                        isError = true
                    )

                if (messages.isEmpty()) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Messages array cannot be empty"}""")),
                        isError = true
                    )
                }

                val context = args["context"]?.jsonPrimitive?.contentOrNull

                val result = bridge.prompt(messages, context)
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
