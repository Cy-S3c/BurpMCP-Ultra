package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.CollaboratorPayload
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.collaborator.InteractionType
import burp.api.montoya.collaborator.PayloadOption
import burp.api.montoya.collaborator.SecretKey
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.CollaboratorClientState
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.Base64

/**
 * Bridge wrapping the Montoya Collaborator API (Pro only).
 *
 * Provides methods to create and restore Collaborator clients, generate
 * payloads, and poll for out-of-band interactions (DNS, HTTP, SMTP).
 *
 * All methods guard against [UnsupportedOperationException] thrown when
 * running on Burp Suite Community Edition.
 */
class CollaboratorBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {

    /**
     * Creates a new Collaborator client and stores it in the state manager.
     *
     * @return JSON object with client ID, server address, and creation timestamp.
     */
    fun createClient(): JsonObject {
        return try {
            val client = api.collaborator().createClient()
            val server = client.server().address()
            val clientId = stateManager.generateId("collab")

            val clientState = CollaboratorClientState(
                clientId = clientId,
                client = client,
                server = server,
                createdAt = Instant.now().toString()
            )
            stateManager.collaboratorClients[clientId] = clientState

            buildJsonObject {
                put("client_id", clientId)
                put("server", server)
                put("created_at", clientState.createdAt)
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Collaborator API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to create Collaborator client: ${e.message}")
            }
        }
    }

    /**
     * Restores a previously created Collaborator client using its secret key.
     *
     * @param secretKey Base64-encoded secret key from a previous client session.
     * @return JSON object with client ID, server address, and creation timestamp.
     */
    fun restoreClient(secretKey: String): JsonObject {
        return try {
            val key = SecretKey.secretKey(secretKey)
            val client = api.collaborator().restoreClient(key)
            val server = client.server().address()
            val clientId = stateManager.generateId("collab")

            val clientState = CollaboratorClientState(
                clientId = clientId,
                client = client,
                server = server,
                createdAt = Instant.now().toString()
            )
            stateManager.collaboratorClients[clientId] = clientState

            buildJsonObject {
                put("client_id", clientId)
                put("server", server)
                put("restored", true)
                put("created_at", clientState.createdAt)
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Collaborator API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to restore Collaborator client: ${e.message}")
            }
        }
    }

    /**
     * Generates a new Collaborator payload for the given client.
     *
     * @param clientId The Collaborator client identifier.
     * @param customData Optional custom data to embed in the payload.
     * @return JSON object with the generated payload string and full interaction URL.
     */
    fun generatePayload(clientId: String, customData: String?): JsonObject {
        val clientState = stateManager.collaboratorClients[clientId]
            ?: return buildJsonObject { put("error", "Client not found: $clientId") }

        return try {
            val client = clientState.client as CollaboratorClient
            val payload: CollaboratorPayload = if (customData != null) {
                client.generatePayload(customData)
            } else {
                client.generatePayload()
            }

            // CollaboratorPayload.toString() already returns the full address
            // (subdomain + server), so it must NOT be concatenated with the
            // server address again.
            val payloadStr = payload.toString()

            buildJsonObject {
                put("client_id", clientId)
                put("payload", payloadStr)
                put("interaction_url", "http://$payloadStr")
                if (customData != null) {
                    put("custom_data", customData)
                }
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to generate payload: ${e.message}")
            }
        }
    }

    /**
     * Generates a payload using Burp's DEFAULT Collaborator payload generator.
     *
     * Unlike [generatePayload], these payloads are linked to Burp's native
     * Collaborator tab — any interactions appear in the Collaborator results
     * tab that was open when the payload was generated. The trade-off: the
     * default generator is generate-only, so these interactions CANNOT be
     * polled through the API ([pollInteractions] will not see them); they must
     * be read in the native Collaborator tab.
     *
     * @param withoutServerLocation when true, omit the server location from the payload.
     * @return JSON with the payload string, interaction URL/id, and (when present) server + custom data.
     */
    fun generateDefaultPayload(withoutServerLocation: Boolean): JsonObject {
        return try {
            val generator = api.collaborator().defaultPayloadGenerator()
            val payload = if (withoutServerLocation) {
                generator.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION)
            } else {
                generator.generatePayload()
            }

            val payloadStr = payload.toString()
            buildJsonObject {
                put("payload", payloadStr)
                put("interaction_url", "http://$payloadStr")
                put("interaction_id", payload.id().toString())
                payload.server().ifPresent { put("server", it.address()) }
                payload.customData().ifPresent { put("custom_data", it) }
                put(
                    "note",
                    "Linked to Burp's native Collaborator tab; interactions appear there and are NOT pollable via collaborator_poll."
                )
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Collaborator API is not available in Burp Suite Community Edition")
            }
        } catch (e: IllegalStateException) {
            buildJsonObject {
                put("error", "Burp Collaborator is disabled: ${e.message}")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to generate default payload: ${e.message}")
            }
        }
    }

    /**
     * Polls for Collaborator interactions on the given client.
     *
     * @param clientId The Collaborator client identifier.
     * @param type Optional interaction type filter: "dns", "http", "smtp".
     * @param payloadId Optional specific payload ID to filter by.
     * @return JSON object with a list of interactions.
     */
    fun pollInteractions(clientId: String, type: String?, payloadId: String?): JsonObject {
        val clientState = stateManager.collaboratorClients[clientId]
            ?: return buildJsonObject { put("error", "Client not found: $clientId") }

        return try {
            val client = clientState.client as CollaboratorClient

            // Fetch interactions: narrow by payloadId at the server level when
            // provided, otherwise fetch all.
            val interactions: List<Interaction> = if (payloadId != null) {
                client.getInteractions(InteractionFilter.interactionPayloadFilter(payloadId))
            } else {
                client.getAllInteractions()
            }

            // Apply the type post-filter unconditionally when a type is
            // specified, regardless of whether a payloadId filter was used.
            val filtered = if (type != null) {
                val interactionType = when (type.lowercase()) {
                    "dns" -> InteractionType.DNS
                    "http" -> InteractionType.HTTP
                    "smtp" -> InteractionType.SMTP
                    else -> throw IllegalArgumentException("Invalid type '$type'. Allowed: dns, http, smtp")
                }
                interactions.filter { it.type() == interactionType }
            } else {
                interactions
            }

            // Emit events for each interaction
            filtered.forEach { interaction ->
                val interactionData = serializeInteraction(interaction)
                eventBus.emit("collaborator.interaction", interactionData)
            }

            buildJsonObject {
                put("client_id", clientId)
                put("interaction_count", filtered.size)
                put("interactions", buildJsonArray {
                    filtered.forEach { interaction ->
                        add(serializeInteraction(interaction))
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to poll interactions: ${e.message}")
            }
        }
    }

    /**
     * Returns the Collaborator server address for the given client.
     *
     * @param clientId The Collaborator client identifier.
     * @return JSON object with the server address.
     */
    fun getServerInfo(clientId: String): JsonObject {
        val clientState = stateManager.collaboratorClients[clientId]
            ?: return buildJsonObject { put("error", "Client not found: $clientId") }

        return try {
            val client = clientState.client as CollaboratorClient
            val serverAddress = client.server().address()

            buildJsonObject {
                put("client_id", clientId)
                put("server_address", serverAddress)
                put("created_at", clientState.createdAt)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to get server info: ${e.message}")
            }
        }
    }

    /**
     * Returns the secret key for the given Collaborator client, base64-encoded.
     * This key can be used to restore the client in a future session.
     *
     * @param clientId The Collaborator client identifier.
     * @return JSON object with the secret key.
     */
    fun getSecret(clientId: String): JsonObject {
        val clientState = stateManager.collaboratorClients[clientId]
            ?: return buildJsonObject { put("error", "Client not found: $clientId") }

        return try {
            val client = clientState.client as CollaboratorClient
            val secretKey = client.getSecretKey().toString()

            buildJsonObject {
                put("client_id", clientId)
                put("secret_key", secretKey)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to get secret key: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    /**
     * Serializes a single Collaborator [Interaction] to a [JsonObject] with
     * type-specific detail fields.
     */
    private fun serializeInteraction(interaction: Interaction): JsonObject {
        return buildJsonObject {
            put("type", interaction.type().name.lowercase())
            put("id", interaction.id().toString())
            put("client_ip", interaction.clientIp().hostAddress)
            put("client_port", interaction.clientPort())
            put("timestamp", interaction.timeStamp().toString())

            // Interaction-level custom data: the ≤16-char marker embedded via
            // generatePayload(customData), echoed back when the hit occurs.
            val customDataOpt = interaction.customData()
            if (customDataOpt.isPresent) put("custom_data", customDataOpt.get())

            when (interaction.type()) {
                InteractionType.DNS -> {
                    put("dns_details", buildJsonObject {
                        try {
                            val dnsDetailsOpt = interaction.dnsDetails()
                            if (dnsDetailsOpt.isPresent) {
                                val dnsDetails = dnsDetailsOpt.get()
                                put("query_type", dnsDetails.queryType().name)
                                // query() is the raw DNS request packet (ByteArray),
                                // not a hostname — decode the QNAME for a readable
                                // value and keep the raw bytes as hex for forensics.
                                val rawQuery = dnsDetails.query().bytes
                                DnsQueryDecoder.decodeQName(rawQuery)?.let { put("query_name", it) }
                                put("query_hex", rawQuery.joinToString("") { "%02x".format(it.toInt() and 0xFF) })
                            } else {
                                put("error", "DNS details not available")
                            }
                        } catch (_: Exception) {
                            put("error", "Could not read DNS details")
                        }
                    })
                }
                InteractionType.HTTP -> {
                    put("http_details", buildJsonObject {
                        try {
                            val httpDetailsOpt = interaction.httpDetails()
                            if (httpDetailsOpt.isPresent) {
                                val httpDetails = httpDetailsOpt.get()
                                put("protocol", httpDetails.protocol().name)
                                put("request_method", httpDetails.requestResponse().request()?.method() ?: "")
                                put("request_url", httpDetails.requestResponse().request()?.url() ?: "")
                                put("response_status",
                                    httpDetails.requestResponse().response()?.statusCode()?.toLong() ?: 0L)
                            } else {
                                put("error", "HTTP details not available")
                            }
                        } catch (_: Exception) {
                            put("error", "Could not read HTTP details")
                        }
                    })
                }
                InteractionType.SMTP -> {
                    put("smtp_details", buildJsonObject {
                        try {
                            val smtpDetailsOpt = interaction.smtpDetails()
                            if (smtpDetailsOpt.isPresent) {
                                val smtpDetails = smtpDetailsOpt.get()
                                put("protocol", smtpDetails.protocol().name)
                                put("conversation", smtpDetails.conversation())
                            } else {
                                put("error", "SMTP details not available")
                            }
                        } catch (_: Exception) {
                            put("error", "Could not read SMTP details")
                        }
                    })
                }
            }
        }
    }
}
