package com.burpmcp.ultra.tools.scope

import com.burpmcp.ultra.bridge.ScopeBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ScopeTools {

    fun register(server: Server, bridge: ScopeBridge) {

        server.addTool(
            name = "scope_check",
            description = "Check whether a given URL is within Burp Suite's target scope. " +
                "Returns true if the URL matches the current scope include/exclude rules. " +
                "Parameters: url (the full URL to check, e.g. 'https://example.com/path').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Full URL to check against scope") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: url"}""")),
                        isError = true
                    )

                val result = bridge.check(url)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "scope_include",
            description = "Add a URL to Burp Suite's target scope. All URLs matching the " +
                "specified pattern will be included in scope for scanning, proxy interception, " +
                "and other scope-aware operations. Parameters: url (the URL to include in " +
                "scope, e.g. 'https://example.com').",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "URL to include in scope") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: url"}""")),
                        isError = true
                    )

                val result = bridge.include(url)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "scope_exclude",
            description = "Exclude a URL from Burp Suite's target scope. The specified URL " +
                "pattern will be excluded even if it matches an include rule. Useful for " +
                "preventing scanning of logout endpoints, admin panels, or third-party " +
                "resources. Parameters: url (the URL to exclude from scope).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "URL to exclude from scope") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: url"}""")),
                        isError = true
                    )

                val result = bridge.exclude(url)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "scope_get_config",
            description = "Retrieve the current Burp Suite target scope configuration. " +
                "Returns the scope include and exclude rules as configured in the " +
                "Target > Scope settings. No parameters required.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {},
                required = emptyList()
            )
        ) { _ ->
            try {
                val result = bridge.getConfig()
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
