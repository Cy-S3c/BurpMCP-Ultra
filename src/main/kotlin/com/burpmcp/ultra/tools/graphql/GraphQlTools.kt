package com.burpmcp.ultra.tools.graphql

import com.burpmcp.ultra.bridge.GraphQlBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `graphql_probe` MCP tool. */
object GraphQlTools {
    fun register(server: Server, bridge: GraphQlBridge) {
        server.addTool(
            name = "graphql_probe",
            description = "Probe a GraphQL endpoint: run introspection and summarize the schema (root query/mutation " +
                "fields); if introspection is disabled, enumerate fields via 'Did you mean' suggestions. " +
                "Respects the operator scope policy (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "GraphQL endpoint URL (e.g. https://target/graphql)") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'url' is required"}""")),
                        isError = true
                    )
                CallToolResult(content = listOf(TextContent(bridge.probe(url).toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())),
                    isError = true
                )
            }
        }
    }
}
