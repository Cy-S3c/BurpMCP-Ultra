package com.burpmcp.ultra.tools.websocket

import com.burpmcp.ultra.bridge.WebSocketBridge
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object WebSocketTools {

    fun register(server: Server, bridge: WebSocketBridge, stateManager: StateManager) {

        server.addTool(
            name = "websocket_create",
            description = "Create a new WebSocket connection to a target URL. Constructs an " +
                "HTTP upgrade request and establishes a WebSocket connection through Burp. " +
                "All messages are automatically captured and available via websocket_get_messages. " +
                "Parameters: url (WebSocket URL, e.g. 'wss://example.com/ws', required), " +
                "headers (optional object of additional HTTP headers as key-value pairs), " +
                "subprotocol (optional string, WebSocket subprotocol to request).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("url") { put("type", "string"); put("description", "WebSocket URL, e.g. 'wss://example.com/ws'") }
                    putJsonObject("headers") { put("type", "object"); put("description", "Additional HTTP headers as key-value pairs") }
                    putJsonObject("subprotocol") { put("type", "string"); put("description", "WebSocket subprotocol to request") }
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

                val headers = args["headers"]?.jsonObject?.let { obj ->
                    obj.entries.associate { (k, v) -> k to v.jsonPrimitive.content }
                }
                val subprotocol = args["subprotocol"]?.jsonPrimitive?.contentOrNull

                val result = bridge.createConnection(url, headers, subprotocol)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "websocket_send_text",
            description = "Send a text message on an existing WebSocket connection. The message " +
                "is tracked and can be retrieved later via websocket_get_messages. " +
                "Parameters: connection_id (string, the WebSocket connection ID, required), " +
                "message (string, the text message to send, required).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    putJsonObject("message") { put("type", "string"); put("description", "The text message to send") }
                },
                required = listOf("connection_id", "message")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args["connection_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: connection_id"}""")),
                        isError = true
                    )
                val message = args["message"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: message"}""")),
                        isError = true
                    )

                val result = bridge.sendText(connectionId, message)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "websocket_send_binary",
            description = "Send a binary message on an existing WebSocket connection. The data " +
                "must be base64-encoded and will be decoded before transmission. " +
                "Parameters: connection_id (string, the WebSocket connection ID, required), " +
                "data (string, base64-encoded binary data to send, required).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    putJsonObject("data") { put("type", "string"); put("description", "Base64-encoded binary data to send") }
                },
                required = listOf("connection_id", "data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args["connection_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: connection_id"}""")),
                        isError = true
                    )
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: data"}""")),
                        isError = true
                    )

                val result = bridge.sendBinary(connectionId, data)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "websocket_close",
            description = "Close an existing WebSocket connection. The connection status is " +
                "updated to 'closed' and all captured messages remain available for retrieval. " +
                "Parameters: connection_id (string, the WebSocket connection ID to close, required).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID to close") }
                },
                required = listOf("connection_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args["connection_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: connection_id"}""")),
                        isError = true
                    )

                val result = bridge.close(connectionId)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "websocket_list",
            description = "List all tracked WebSocket connections, including both programmatically " +
                "created connections and those intercepted through Burp's proxy. Returns " +
                "connection summaries with ID, URL, status, and message counts. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.listConnections()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "websocket_get_messages",
            description = "Retrieve messages from a specific WebSocket connection with optional " +
                "filtering and pagination. Supports cursor-based polling via since_index. " +
                "Parameters: connection_id (string, required), direction (optional string, " +
                "filter by 'client_to_server' or 'server_to_client'), since_index (optional " +
                "integer, only return messages with index greater than this value, default -1 " +
                "for all), max_results (optional integer, maximum messages to return, default 100).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("connection_id") { put("type", "string"); put("description", "The WebSocket connection ID") }
                    putJsonObject("direction") { put("type", "string"); put("description", "Filter by 'client_to_server' or 'server_to_client'") }
                    putJsonObject("since_index") { put("type", "integer"); put("description", "Only return messages with index greater than this (default -1 for all)") }
                    putJsonObject("max_results") { put("type", "integer"); put("description", "Maximum messages to return (default 100)") }
                },
                required = listOf("connection_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val connectionId = args["connection_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: connection_id"}""")),
                        isError = true
                    )
                val direction = args["direction"]?.jsonPrimitive?.contentOrNull
                val sinceIndex = args["since_index"]?.jsonPrimitive?.longOrNull ?: -1L
                val maxResults = args["max_results"]?.jsonPrimitive?.intOrNull ?: 100

                val result = bridge.getMessages(connectionId, direction, sinceIndex, maxResults)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "websocket_set_intercept_rule",
            description = "Create or update a WebSocket message interception rule. Rules can " +
                "modify, drop, or tag messages matching specified criteria. Rules are evaluated " +
                "against all WebSocket traffic passing through Burp. " +
                "Parameters: rule_id (optional string, unique ID; auto-generated if not " +
                "provided), match_url (optional string, regex to match against WebSocket URL), " +
                "match_message (optional string, regex to match against message content), " +
                "direction (optional string, 'client_to_server', 'server_to_client', or " +
                "'both', default 'both'), action (string, 'modify', 'drop', or 'tag', required), " +
                "modify_regex (optional string, regex for content replacement when action is " +
                "'modify'), modify_replacement (optional string, replacement for regex matches), " +
                "tag_comment (optional string, comment to attach when action is 'tag'), " +
                "enabled (optional boolean, whether the rule is active, default true).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("rule_id") { put("type", "string"); put("description", "Unique rule ID; auto-generated if not provided") }
                    putJsonObject("match_url") { put("type", "string"); put("description", "Regex to match against WebSocket URL") }
                    putJsonObject("match_message") { put("type", "string"); put("description", "Regex to match against message content") }
                    putJsonObject("direction") { put("type", "string"); put("description", "'client_to_server', 'server_to_client', or 'both' (default 'both')") }
                    putJsonObject("action") { put("type", "string"); put("description", "'modify', 'drop', or 'tag'") }
                    putJsonObject("modify_regex") { put("type", "string"); put("description", "Regex for content replacement when action is 'modify'") }
                    putJsonObject("modify_replacement") { put("type", "string"); put("description", "Replacement for regex matches") }
                    putJsonObject("tag_comment") { put("type", "string"); put("description", "Comment to attach when action is 'tag'") }
                    putJsonObject("enabled") { put("type", "boolean"); put("description", "Whether the rule is active (default true)") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val ruleId = args["rule_id"]?.jsonPrimitive?.contentOrNull
                val matchUrl = args["match_url"]?.jsonPrimitive?.contentOrNull
                val matchMessage = args["match_message"]?.jsonPrimitive?.contentOrNull
                val direction = args["direction"]?.jsonPrimitive?.contentOrNull ?: "both"
                val action = args["action"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: action"}""")),
                        isError = true
                    )

                if (action !in listOf("modify", "drop", "tag")) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Invalid action: $action. Must be 'modify', 'drop', or 'tag'"}""")),
                        isError = true
                    )
                }

                val modifyRegex = args["modify_regex"]?.jsonPrimitive?.contentOrNull
                val modifyReplacement = args["modify_replacement"]?.jsonPrimitive?.contentOrNull
                val tagComment = args["tag_comment"]?.jsonPrimitive?.contentOrNull
                val enabled = args["enabled"]?.jsonPrimitive?.booleanOrNull ?: true

                val result = bridge.setInterceptRule(
                    ruleId, matchUrl, matchMessage, direction, action,
                    modifyRegex, modifyReplacement, tagComment, enabled
                )
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
