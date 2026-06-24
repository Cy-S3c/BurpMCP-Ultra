package com.burpmcp.ultra.tools.bambda

import com.burpmcp.ultra.bridge.BambdaBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object BambdaTools {

    fun register(server: Server, bridge: BambdaBridge) {

        // 1. bambda_import
        server.addTool(
            name = "bambda_import",
            description = "Import a Bambda script into Burp Suite. Bambda expressions " +
                "are Java-like lambda expressions used to customize Burp Suite's " +
                "behavior, such as proxy history filters, HTTP match-and-replace " +
                "rules, and custom column definitions. Parameters: script (required, " +
                "the Bambda script content as a Java lambda expression string).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("script") { put("type", "string"); put("description", "The Bambda script content as a Java lambda expression string") }
                },
                required = listOf("script")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val script = args["script"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: script"}""")),
                        isError = true
                    )

                if (script.isBlank()) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Script cannot be empty"}""")),
                        isError = true
                    )
                }

                val result = bridge.importBambda(script)
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
