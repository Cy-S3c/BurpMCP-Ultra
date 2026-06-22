package com.burpmcp.ultra.tools.accesscontrol

import com.burpmcp.ultra.bridge.AccessControlBridge
import com.burpmcp.ultra.core.asJsonObjectList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `access_control_sweep` MCP tool. */
object AccessControlTools {
    fun register(server: Server, bridge: AccessControlBridge) {
        server.addTool(
            name = "access_control_sweep",
            description = "Batch broken-access-control / IDOR test: replays each request under every identity and " +
                "flags where a lower-privilege or unauthenticated identity gets a response matching a higher-privilege " +
                "one. Scales auth_diff across many endpoints in one call. Provide 'identities' as " +
                "[{name, header_name?, header_value?}] — a name of none/unauth strips auth headers. Scope-gated " +
                "(mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("requests") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "Requests to test: each {raw_request, host, port?, use_tls?}")
                    }
                    putJsonObject("identities") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "Identities: each {name, header_name?, header_value?}; name none/unauth strips auth")
                    }
                },
                required = listOf("requests", "identities")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val requests = args["requests"].asJsonObjectList()
                    ?: return@addTool err("Parameter 'requests' (array of objects) is required")
                val identities = args["identities"].asJsonObjectList()
                    ?: return@addTool err("Parameter 'identities' (array of objects) is required")
                CallToolResult(content = listOf(TextContent(bridge.sweep(requests, identities).toString())))
            } catch (e: Exception) {
                err(e.message)
            }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
