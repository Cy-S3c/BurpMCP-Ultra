package com.burpmcp.ultra.tools.webprobe

import com.burpmcp.ultra.bridge.WebProbeBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers cors_probe + recon_fingerprint. */
object WebProbeTools {
    fun register(server: Server, bridge: WebProbeBridge) {

        server.addTool(
            name = "cors_probe",
            description = "Probe a URL's CORS policy by sending crafted Origin headers (reflected, null) and " +
                "classifying the Access-Control-Allow-Origin/-Credentials response. Flags reflected-origin and " +
                "null-origin misconfigurations. Respects the operator scope policy.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'url' is required")
                CallToolResult(content = listOf(TextContent(bridge.corsProbe(url).toString())))
            } catch (e: Exception) { err(e.message) }
        }

        server.addTool(
            name = "recon_fingerprint",
            description = "Fingerprint server/tech/WAF/framework from a single GET (Server, X-Powered-By, " +
                "Set-Cookie, WAF headers, and body markers). Drives downstream payload selection. Respects scope policy.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "Target URL") }
                },
                required = listOf("url")
            )
        ) { request ->
            try {
                val url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull
                    ?: return@addTool err("Parameter 'url' is required")
                CallToolResult(content = listOf(TextContent(bridge.fingerprint(url).toString())))
            } catch (e: Exception) { err(e.message) }
        }
    }

    private fun err(msg: String?): CallToolResult =
        CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", msg ?: "Unknown error") }.toString())), isError = true)
}
