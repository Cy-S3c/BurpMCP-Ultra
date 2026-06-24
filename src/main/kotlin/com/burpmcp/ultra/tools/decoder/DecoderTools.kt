package com.burpmcp.ultra.tools.decoder

import com.burpmcp.ultra.bridge.DecoderBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object DecoderTools {

    fun register(server: Server, bridge: DecoderBridge) {

        server.addTool(
            name = "decoder_send",
            description = "Send data to Burp Suite's Decoder tool for manual encoding, " +
                "decoding, and hashing operations. The data will appear in a new Decoder " +
                "tab where various transformations can be applied interactively. " +
                "Parameters: data (string, the data to send to the Decoder).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("data") { put("type", "string"); put("description", "The data to send to the Decoder") }
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: data"}""")),
                        isError = true
                    )

                val result = bridge.send(data)
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
