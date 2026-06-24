package com.burpmcp.ultra.tools.logging

import com.burpmcp.ultra.bridge.LoggingBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object LoggingTools {

    fun register(server: Server, bridge: LoggingBridge) {

        // 1. log_message
        server.addTool(
            name = "log_message",
            description = "Write a message to Burp Suite's extension output or error log stream. " +
                "Messages appear in the Extensions > Output/Errors tab. " +
                "Parameters: message (string, the text to log), " +
                "level (string, 'output' for normal output or 'error' for error stream; defaults to 'output').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("message") { put("type", "string"); put("description", "The text to log") }
                    putJsonObject("level") { put("type", "string"); put("description", "'output' for normal output or 'error' for error stream, default 'output'") }
                },
                required = listOf("message")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val message = args["message"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: message"}""")),
                        isError = true
                    )
                val level = args["level"]?.jsonPrimitive?.contentOrNull ?: "output"

                val result = bridge.logMessage(message, level)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 2. log_event
        server.addTool(
            name = "log_event",
            description = "Raise an event in Burp Suite's event log panel at a specified severity level. " +
                "Events appear in the Dashboard > Event log. " +
                "Parameters: message (string, the event message), " +
                "level (string, one of 'debug', 'info', 'error', 'critical'; defaults to 'info').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("message") { put("type", "string"); put("description", "The event message") }
                    putJsonObject("level") { put("type", "string"); put("description", "One of 'debug', 'info', 'error', 'critical', default 'info'") }
                },
                required = listOf("message")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val message = args["message"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: message"}""")),
                        isError = true
                    )
                val level = args["level"]?.jsonPrimitive?.contentOrNull ?: "info"

                val validLevels = listOf("debug", "info", "error", "critical")
                if (level.lowercase() !in validLevels) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(
                            """{"error":"Invalid level: $level. Valid levels: ${validLevels.joinToString(", ")}"}"""
                        )),
                        isError = true
                    )
                }

                val result = bridge.logEvent(message, level)
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
