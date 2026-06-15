package com.burpmcp.ultra.tools.findings

import com.burpmcp.ultra.bridge.FindingsBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the findings-memory tools: `findings_add` (deduplicated) and
 * `findings_list`. Gives the agent persistent recall of confirmed/suspected
 * issues across a session for triage and reporting.
 */
object FindingsTools {
    fun register(server: Server, bridge: FindingsBridge) {
        server.addTool(
            name = "findings_add",
            description = "Record a confirmed or suspected finding in the agent's deduplicated findings store " +
                "(working memory, separate from Burp's scanner). Re-adding the same type+url+location is deduped. " +
                "Use to remember bugs you've confirmed so you can triage/report them later.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("type") { put("type", "string"); put("description", "Vulnerability type, e.g. xss, sqli, idor, ssrf, info_leak") }
                    putJsonObject("severity") { put("type", "string"); put("description", "critical|high|medium|low|info (default info)") }
                    putJsonObject("url") { put("type", "string"); put("description", "Affected URL") }
                    putJsonObject("location") { put("type", "string"); put("description", "Where it lives: param:name, header:name, body, path") }
                    putJsonObject("detail") { put("type", "string"); put("description", "Description / how to reproduce") }
                    putJsonObject("evidence") { put("type", "string"); put("description", "Evidence (payload, response excerpt)") }
                },
                required = listOf("type", "url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val type = a["type"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'type' is required")
                val url = a["url"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'url' is required")
                val result = bridge.add(
                    type,
                    a["severity"]?.jsonPrimitive?.contentOrNull ?: "info",
                    url,
                    a["location"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["detail"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["evidence"]?.jsonPrimitive?.contentOrNull ?: ""
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                err(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "findings_list",
            description = "List the recorded findings, optionally filtered by severity and/or type.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("severity") { put("type", "string"); put("description", "Filter by severity") }
                    putJsonObject("type") { put("type", "string"); put("description", "Filter by type") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val result = bridge.list(a["severity"]?.jsonPrimitive?.contentOrNull, a["type"]?.jsonPrimitive?.contentOrNull)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                err(e.message ?: "Unknown error")
            }
        }
    }

    private fun err(msg: String): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg) }.toString())), isError = true)
}
