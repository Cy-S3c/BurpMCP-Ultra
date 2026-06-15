package com.burpmcp.ultra.tools.recon

import com.burpmcp.ultra.bridge.ReconBridge
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the recon/discovery tools: JS endpoint harvest, content discovery, param mining. */
object ReconTools {
    fun register(server: Server, bridge: ReconBridge) {

        server.addTool(
            name = "recon_js_endpoints",
            description = "Harvest endpoint paths and URLs from JavaScript responses already in proxy history " +
                "(SPAs leak their API surface in JS). Browse the target first, then run this.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("max_items") { put("type", "integer"); put("description", "Max recent history items to scan (default 500)") }
                    putJsonObject("host_filter") { put("type", "string"); put("description", "Optional host regex filter") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val result = bridge.jsEndpoints(
                    a["max_items"]?.jsonPrimitive?.intOrNull ?: 500,
                    a["host_filter"]?.jsonPrimitive?.contentOrNull
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "recon_content_discovery",
            description = "Brute-force a wordlist of paths under a base URL, calibrating against a known-missing " +
                "path to filter soft-404s. Returns paths whose status/size differ from the catch-all baseline. " +
                "Respects the operator scope policy (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("base_url") { put("type", "string"); put("description", "Base URL, e.g. https://target.com") }
                    putJsonObject("paths") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate paths (with or without leading /)") }
                },
                required = listOf("base_url", "paths")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val baseUrl = a["base_url"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'base_url' is required")
                val paths = a["paths"].asStringList() ?: return@addTool err("Parameter 'paths' (array) is required")
                CallToolResult(content = listOf(TextContent(bridge.contentDiscovery(baseUrl, paths).toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "recon_param_mine",
            description = "Probe candidate parameter names on a URL and flag those reflected in the response — " +
                "hidden params are where IDOR/XSS/SSRF often hide. Respects the operator scope policy.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                    putJsonObject("candidates") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate parameter names") }
                },
                required = listOf("url", "candidates")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val url = a["url"]?.jsonPrimitive?.contentOrNull ?: return@addTool err("Parameter 'url' is required")
                val candidates = a["candidates"].asStringList() ?: return@addTool err("Parameter 'candidates' (array) is required")
                CallToolResult(content = listOf(TextContent(bridge.paramMine(url, candidates).toString())))
            } catch (e: Exception) { err(e.message) }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
