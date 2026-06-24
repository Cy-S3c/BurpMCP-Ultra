package com.burpmcp.ultra.tools.session

import com.burpmcp.ultra.bridge.HttpBridge
import com.burpmcp.ultra.bridge.SessionBridge
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * MCP tools for managing session handling rules. Rules define how to
 * extract dynamic tokens from HTTP responses and inject them into
 * subsequent requests (e.g. CSRF tokens, session tokens).
 *
 * The HttpBridge parameter is accepted to match the ToolRegistry call
 * signature; the actual session logic is handled by [SessionBridge]
 * which operates purely on [StateManager].
 */
object SessionTools {

    @Suppress("UNUSED_PARAMETER")
    fun register(server: Server, httpBridge: HttpBridge, stateManager: StateManager) {
        val bridge = SessionBridge(stateManager)

        // 1. session_create_token_rule
        server.addTool(
            name = "session_create_token_rule",
            description = "Create a session handling rule that extracts a dynamic value (e.g. CSRF " +
                "token, session ID) from HTTP responses and injects it into subsequent requests. " +
                "Parameters: rule_name (string, unique name for this rule), " +
                "scope (string, 'all', 'suite', or 'custom'), " +
                "scope_pattern (optional string, URL pattern when scope is 'custom'), " +
                "extract_from (string, 'header' or 'body'), " +
                "extract_header_name (optional string, header name when extracting from headers), " +
                "extract_regex (string, regex with a capture group for the value to extract), " +
                "inject_into (string, 'header', 'body', or 'cookie'), " +
                "inject_name (string, name of the header/cookie/parameter to inject into), " +
                "inject_value_template (string, template where {value} is replaced with extracted value), " +
                "enabled (boolean, whether the rule is active; defaults to true).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_name") { put("type", "string"); put("description", "Unique name for this rule") }
                    putJsonObject("scope") { put("type", "string"); put("description", "'all', 'suite', or 'custom'") }
                    putJsonObject("scope_pattern") { put("type", "string"); put("description", "URL pattern when scope is 'custom'") }
                    putJsonObject("extract_from") { put("type", "string"); put("description", "'header' or 'body'") }
                    putJsonObject("extract_header_name") { put("type", "string"); put("description", "Header name when extracting from headers") }
                    putJsonObject("extract_regex") { put("type", "string"); put("description", "Regex with a capture group for the value to extract") }
                    putJsonObject("inject_into") { put("type", "string"); put("description", "'header', 'body', or 'cookie'") }
                    putJsonObject("inject_name") { put("type", "string"); put("description", "Name of the header/cookie/parameter to inject into") }
                    putJsonObject("inject_value_template") { put("type", "string"); put("description", "Template where {value} is replaced with extracted value") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active; defaults to true") }
                },
                required = listOf("rule_name", "scope", "extract_from", "extract_regex", "inject_into", "inject_name", "inject_value_template")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val ruleName = args["rule_name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: rule_name"}""")),
                        isError = true
                    )
                val scope = args["scope"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: scope"}""")),
                        isError = true
                    )
                val scopePattern = args["scope_pattern"]?.jsonPrimitive?.contentOrNull
                val extractFrom = args["extract_from"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: extract_from"}""")),
                        isError = true
                    )
                val extractHeaderName = args["extract_header_name"]?.jsonPrimitive?.contentOrNull
                val extractRegex = args["extract_regex"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: extract_regex"}""")),
                        isError = true
                    )
                val injectInto = args["inject_into"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: inject_into"}""")),
                        isError = true
                    )
                val injectName = args["inject_name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: inject_name"}""")),
                        isError = true
                    )
                val injectValueTemplate = args["inject_value_template"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: inject_value_template"}""")),
                        isError = true
                    )
                val enabled = args["enabled"]?.jsonPrimitive?.booleanOrNull ?: true

                val result = bridge.createTokenRule(
                    ruleName, scope, scopePattern, extractFrom, extractHeaderName,
                    extractRegex, injectInto, injectName, injectValueTemplate, enabled
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 2. session_list_rules
        server.addTool(
            name = "session_list_rules",
            description = "List all session handling rules including their extraction/injection " +
                "configuration, enabled status, and the last extracted value for each rule. " +
                "No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.listRules()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 3. session_remove_rule
        server.addTool(
            name = "session_remove_rule",
            description = "Remove a session handling rule by its name. The rule will no longer " +
                "extract or inject values for matching requests. " +
                "Parameters: rule_name (string, the name of the rule to remove).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_name") { put("type", "string"); put("description", "The name of the rule to remove") }
                },
                required = listOf("rule_name")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val ruleName = args["rule_name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: rule_name"}""")),
                        isError = true
                    )
                val result = bridge.removeRule(ruleName)
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
