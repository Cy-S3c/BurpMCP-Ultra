package com.burpmcp.ultra.tools.passiveintel

import com.burpmcp.ultra.bridge.PassiveIntelBridge
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object PassiveIntelTools {
    fun register(server: Server, bridge: PassiveIntelBridge) {
        server.addTool(
            name = "passive_intel",
            description = """Scan proxy history for sensitive data: AWS keys, API tokens, JWTs, emails, internal IPs, S3 buckets, stack traces, SQL errors, server versions, sensitive paths, and 30+ other patterns. Zero-effort intelligence gathering from traffic already captured.

Parameters: max_items (int, default 1000), in_scope_only (bool, default false), categories (optional array of pattern names to check), host_filter (optional regex).

Available categories: aws_access_key, aws_secret_key, google_api_key, github_token, slack_token, stripe_key, jwt_token, bearer_token, basic_auth, private_key, email_address, ipv4_internal, s3_bucket, azure_storage, gcs_bucket, internal_url, graphql_endpoint, api_endpoint, stack_trace, sql_error, debug_info, server_version, framework_version, php_version, sensitive_path""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("max_items") { put("type", "integer"); put("description", "Maximum proxy history items to scan, default 1000") }
                    putJsonObject("in_scope_only") { put("type", "boolean"); put("description", "Only scan in-scope items, default false") }
                    putJsonObject("categories") {
                        put("type", "array")
                        put("description", "Optional array of pattern names to check")
                        putJsonObject("items") { put("type", "string") }
                    }
                    putJsonObject("host_filter") { put("type", "string"); put("description", "Optional regex to filter by host") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val maxItems = args["max_items"]?.jsonPrimitive?.intOrNull ?: 1000
                val inScopeOnly = args["in_scope_only"]?.jsonPrimitive?.booleanOrNull ?: false
                val categories = args["categories"].asStringList()
                val hostFilter = args["host_filter"]?.jsonPrimitive?.contentOrNull

                val result = bridge.extractIntel(maxItems, inScopeOnly, categories, hostFilter)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(content = listOf(TextContent("""{"error":"${e.message}"}""")), isError = true)
            }
        }
    }
}
