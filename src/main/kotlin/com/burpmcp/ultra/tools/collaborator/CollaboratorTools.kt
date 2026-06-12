package com.burpmcp.ultra.tools.collaborator

import com.burpmcp.ultra.bridge.CollaboratorBridge
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers all 7 Collaborator MCP tools onto the given [Server].
 *
 * Each tool delegates to the [CollaboratorBridge] and catches exceptions so
 * that errors are returned as structured JSON inside a [CallToolResult]
 * rather than propagating unhandled.
 */
object CollaboratorTools {

    fun register(server: Server, bridge: CollaboratorBridge, stateManager: StateManager) {

        // ---------------------------------------------------------------
        // 1. collaborator_create_client
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_create_client",
            description = "Create a new Burp Collaborator client for generating out-of-band (OOB) interaction payloads. " +
                "Returns a client ID and the Collaborator server address. Pro edition only.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { request ->
            try {
                val result = bridge.createClient()
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 2. collaborator_restore_client
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_restore_client",
            description = "Restore a previously created Collaborator client using its secret key. " +
                "This allows resuming interaction polling from a prior session. Pro edition only.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("secret_key") { put("type", "string"); put("description", "Base64-encoded secret key") }
                },
                required = listOf("secret_key")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val secretKey = args["secret_key"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'secret_key' is required (base64-encoded secret key)")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.restoreClient(secretKey)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 3. collaborator_generate_payload
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_generate_payload",
            description = "Generate a unique Collaborator payload (subdomain) for OOB interaction detection. " +
                "Use this payload in injection points to detect blind vulnerabilities (SSRF, blind XSS, etc.). " +
                "Optionally embed custom data in the payload for identification.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", "Collaborator client id") }
                    putJsonObject("custom_data") { put("type", "string"); put("description", "Custom data to embed in the payload") }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val clientId = args["client_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'client_id' is required")
                        }.toString())),
                        isError = true
                    )

                val customData = args["custom_data"]?.jsonPrimitive?.contentOrNull

                val result = bridge.generatePayload(clientId, customData)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 4. collaborator_poll
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_poll",
            description = "Poll for Collaborator interactions (DNS lookups, HTTP requests, SMTP connections) " +
                "that have been triggered by injected payloads. Optionally filter by interaction type or payload ID.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", "Collaborator client id") }
                    putJsonObject("type") { put("type", "string"); put("description", "Filter by interaction type") }
                    putJsonObject("payload_id") { put("type", "string"); put("description", "Filter by payload ID") }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val clientId = args["client_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'client_id' is required")
                        }.toString())),
                        isError = true
                    )

                val type = args["type"]?.jsonPrimitive?.contentOrNull
                val payloadId = args["payload_id"]?.jsonPrimitive?.contentOrNull

                val result = bridge.pollInteractions(clientId, type, payloadId)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 5. collaborator_server_info
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_server_info",
            description = "Get the Collaborator server address and metadata for a given client.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", "Collaborator client id") }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val clientId = args["client_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'client_id' is required")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.getServerInfo(clientId)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 6. collaborator_get_secret
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_get_secret",
            description = "Get the secret key for a Collaborator client. Store this key to restore the client " +
                "in a future session and continue polling for interactions.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("client_id") { put("type", "string"); put("description", "Collaborator client id") }
                },
                required = listOf("client_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val clientId = args["client_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "Parameter 'client_id' is required")
                        }.toString())),
                        isError = true
                    )

                val result = bridge.getSecret(clientId)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }

        // ---------------------------------------------------------------
        // 7. collaborator_default_payload
        // ---------------------------------------------------------------
        server.addTool(
            name = "collaborator_default_payload",
            description = "Generate a Collaborator payload using Burp's DEFAULT generator (no client_id needed). " +
                "Unlike collaborator_generate_payload, these payloads are linked to Burp's NATIVE Collaborator tab — " +
                "interactions show up there but CANNOT be polled via collaborator_poll. Use when you want hits visible " +
                "in Burp's own Collaborator UI rather than via API polling.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("without_server_location") {
                        put("type", "boolean")
                        put("description", "Omit the server location from the payload (default false)")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val withoutServerLocation = args["without_server_location"]?.jsonPrimitive?.booleanOrNull ?: false

                val result = bridge.generateDefaultPayload(withoutServerLocation)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject {
                        put("error", e.message ?: "Unknown error")
                    }.toString())),
                    isError = true
                )
            }
        }
    }
}
