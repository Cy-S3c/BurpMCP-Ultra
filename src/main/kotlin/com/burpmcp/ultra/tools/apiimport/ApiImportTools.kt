package com.burpmcp.ultra.tools.apiimport

import com.burpmcp.ultra.bridge.ApiImportBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ApiImportTools {
    fun register(server: Server, bridge: ApiImportBridge) {
        server.addTool(
            name = "api_import_openapi",
            description = "Import an OpenAPI/Swagger JSON specification. Parses all endpoints, generates HTTP requests " +
                "with sample parameters and bodies, and optionally sends them through Burp (populating sitemap and " +
                "proxy history). Supports OpenAPI 3.x and Swagger 2.0. Parameters: spec_json (required, the full " +
                "JSON spec), base_url (optional override), auth_header/auth_value (optional auth for all requests), " +
                "add_to_scope (bool), add_to_sitemap (bool), send_requests (bool, actually send and get responses).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("spec_json") { put("type", "string"); put("description", "The full OpenAPI/Swagger JSON specification") }
                    putJsonObject("base_url") { put("type", "string"); put("description", "Optional base URL override") }
                    putJsonObject("auth_header") { put("type", "string"); put("description", "Optional auth header name for all requests") }
                    putJsonObject("auth_value") { put("type", "string"); put("description", "Optional auth header value for all requests") }
                    putJsonObject("add_to_scope") { put("type", "boolean"); put("description", "Add discovered endpoints to scope") }
                    putJsonObject("add_to_sitemap") { put("type", "boolean"); put("description", "Add discovered endpoints to the sitemap") }
                    putJsonObject("send_requests") { put("type", "boolean"); put("description", "Actually send requests and get responses") }
                },
                required = listOf("spec_json")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val specJson = args["spec_json"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'spec_json' is required"}""")),
                        isError = true
                    )
                val baseUrl = args["base_url"]?.jsonPrimitive?.contentOrNull
                val authHeader = args["auth_header"]?.jsonPrimitive?.contentOrNull
                val authValue = args["auth_value"]?.jsonPrimitive?.contentOrNull
                val addToScope = args["add_to_scope"]?.jsonPrimitive?.booleanOrNull ?: true
                val addToSitemap = args["add_to_sitemap"]?.jsonPrimitive?.booleanOrNull ?: true
                val sendRequests = args["send_requests"]?.jsonPrimitive?.booleanOrNull ?: false

                val result = bridge.importOpenApi(specJson, baseUrl, authHeader, authValue, addToScope, addToSitemap, sendRequests)
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
