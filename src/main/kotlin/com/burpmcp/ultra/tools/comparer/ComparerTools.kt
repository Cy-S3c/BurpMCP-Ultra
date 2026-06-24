package com.burpmcp.ultra.tools.comparer

import com.burpmcp.ultra.bridge.ComparerBridge
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ComparerTools {

    fun register(server: Server, bridge: ComparerBridge) {

        server.addTool(
            name = "comparer_send",
            description = "Send data items to Burp Suite's Comparer tool for side-by-side " +
                "comparison. Useful for comparing HTTP requests, responses, or any text data " +
                "to identify differences. Parameters: data (array of strings, each string " +
                "becomes a separate item in the Comparer). At least one item is required; " +
                "typically two items are sent for comparison.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("data") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Array of strings, each becomes a separate item in the Comparer") }
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val dataItems = args["data"].asStringList()
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: data (array of strings)"}""")),
                        isError = true
                    )

                if (dataItems.isEmpty()) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"data array must contain at least one item"}""")),
                        isError = true
                    )
                }

                val result = bridge.send(dataItems)
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
