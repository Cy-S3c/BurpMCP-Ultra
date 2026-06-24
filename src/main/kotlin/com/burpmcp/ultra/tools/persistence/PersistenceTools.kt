package com.burpmcp.ultra.tools.persistence

import com.burpmcp.ultra.bridge.PersistenceBridge
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object PersistenceTools {

    fun register(server: Server, bridge: PersistenceBridge) {

        // 1. persistence_store
        server.addTool(
            name = "persistence_store",
            description = "Store a string value in Burp Suite's extension persistence store. " +
                "Data persists across Burp restarts within the same project. " +
                "Parameters: key (string, the storage key), value (string, the value to store).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The storage key") }
                    putJsonObject("value") { put("type", "string"); put("description", "The value to store") }
                },
                required = listOf("key", "value")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: key"}""")),
                        isError = true
                    )
                val value = args["value"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: value"}""")),
                        isError = true
                    )
                val result = bridge.store(key, value)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 2. persistence_get
        server.addTool(
            name = "persistence_get",
            description = "Retrieve a value from Burp Suite's extension persistence store by key. " +
                "Returns the value and a 'found' flag indicating whether the key exists. " +
                "Parameters: key (string, the storage key to look up).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The storage key to look up") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: key"}""")),
                        isError = true
                    )
                val result = bridge.get(key)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 3. persistence_delete
        server.addTool(
            name = "persistence_delete",
            description = "Delete a key-value pair from Burp Suite's extension persistence store. " +
                "Returns whether the key existed before deletion. " +
                "Parameters: key (string, the storage key to delete).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The storage key to delete") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: key"}""")),
                        isError = true
                    )
                val result = bridge.delete(key)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 4. persistence_list
        server.addTool(
            name = "persistence_list",
            description = "List all key-value pairs stored in Burp Suite's extension persistence store. " +
                "Returns the count and an array of all entries with their keys and values. " +
                "No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val result = bridge.list()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 5. preference_store
        server.addTool(
            name = "preference_store",
            description = "Store a value in Burp Suite's user-level preferences. Unlike extension " +
                "persistence data, preferences survive across projects. " +
                "Parameters: key (string, the preference key), value (string, the value to store).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The preference key") }
                    putJsonObject("value") { put("type", "string"); put("description", "The value to store") }
                },
                required = listOf("key", "value")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: key"}""")),
                        isError = true
                    )
                val value = args["value"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: value"}""")),
                        isError = true
                    )
                val result = bridge.preferenceStore(key, value)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 6. preference_get
        server.addTool(
            name = "preference_get",
            description = "Retrieve a value from Burp Suite's user-level preferences by key. " +
                "Preferences are global across projects. " +
                "Parameters: key (string, the preference key to look up).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("key") { put("type", "string"); put("description", "The preference key to look up") }
                },
                required = listOf("key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val key = args["key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: key"}""")),
                        isError = true
                    )
                val result = bridge.preferenceGet(key)
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
