package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.HttpService
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.BinaryMessageAction
import burp.api.montoya.websocket.MessageHandler
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.TextMessageAction
import burp.api.montoya.websocket.WebSocketCreated
import burp.api.montoya.websocket.WebSocketCreatedHandler
import burp.api.montoya.websocket.Direction
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.state.WebSocketConnection
import com.burpmcp.ultra.state.WebSocketInterceptRule
import com.burpmcp.ultra.state.WebSocketMessage
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class WebSocketBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {
    /** Maps connection IDs to the Montoya ExtensionWebSocket object for sending messages. */
    private val webSocketHandles = ConcurrentHashMap<String, ExtensionWebSocket>()

    /** Per-connection message index counter for ordered message tracking. */
    private val messageIndexCounters = ConcurrentHashMap<String, AtomicLong>()

    /**
     * Creates a new WebSocket connection by constructing an HTTP upgrade
     * request and using the Montoya WebSocket API.
     *
     * The returned connection is stored in StateManager and a handler is
     * registered to capture all incoming messages.
     *
     * @param url The WebSocket URL (e.g. "wss://example.com/ws").
     * @param headers Optional map of additional HTTP headers for the upgrade request.
     * @param subprotocol Optional WebSocket subprotocol to request.
     * @return JSON object with the connection ID and status.
     */
    fun createConnection(url: String, headers: Map<String, String>?, subprotocol: String?): JsonObject {
        val connectionId = stateManager.generateId("ws")

        // Parse URL to extract host, port, and path
        val parsedUrl = java.net.URI(url)
        val scheme = parsedUrl.scheme ?: "wss"
        val host = parsedUrl.host ?: return buildErrorJson("Invalid URL: missing host")
        val useTls = scheme == "wss" || scheme == "https"
        val defaultPort = if (useTls) 443 else 80
        val port = if (parsedUrl.port > 0) parsedUrl.port else defaultPort
        val path = if (parsedUrl.rawPath.isNullOrEmpty()) "/" else parsedUrl.rawPath
        val query = if (parsedUrl.rawQuery != null) "?${parsedUrl.rawQuery}" else ""

        // Build the HTTP upgrade request
        val httpService = HttpService.httpService(host, port, useTls)
        var requestBuilder = StringBuilder()
        requestBuilder.append("GET $path$query HTTP/1.1\r\n")
        requestBuilder.append("Host: $host${if (port != defaultPort) ":$port" else ""}\r\n")
        requestBuilder.append("Upgrade: websocket\r\n")
        requestBuilder.append("Connection: Upgrade\r\n")
        requestBuilder.append("Sec-WebSocket-Version: 13\r\n")
        requestBuilder.append("Sec-WebSocket-Key: ${generateWebSocketKey()}\r\n")

        if (subprotocol != null) {
            requestBuilder.append("Sec-WebSocket-Protocol: $subprotocol\r\n")
        }

        headers?.forEach { (name, value) ->
            requestBuilder.append("$name: $value\r\n")
        }

        requestBuilder.append("\r\n")

        val httpRequest = HttpRequest.httpRequest(httpService, requestBuilder.toString())

        // Create the WebSocket connection through Montoya API
        val creation = api.websockets().createWebSocket(httpRequest)
        val webSocketOpt = creation.webSocket()
        if (!webSocketOpt.isPresent) {
            return buildErrorJson("Failed to create WebSocket connection: creation returned no socket")
        }
        val webSocket = webSocketOpt.get()

        // Initialize message index counter
        messageIndexCounters[connectionId] = AtomicLong(0)

        // Create and store the connection state
        val connection = WebSocketConnection(
            connectionId = connectionId,
            url = url,
            createdAt = Instant.now().toString(),
            status = "connected"
        )
        stateManager.websocketConnections[connectionId] = connection
        webSocketHandles[connectionId] = webSocket

        // Register message handlers on the ExtensionWebSocket to capture traffic
        registerExtensionMessageHandlers(webSocket, connectionId)

        // Emit connection created event
        eventBus.emit("websocket.created", buildJsonObject {
            put("connection_id", connectionId)
            put("url", url)
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("connection_id", connectionId)
            put("url", url)
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("status", "connected")
        }
    }

    /**
     * Sends a text message on an existing WebSocket connection.
     *
     * @param connectionId The connection ID to send on.
     * @param message The text message to send.
     * @return JSON object confirming the message was sent.
     */
    fun sendText(connectionId: String, message: String): JsonObject {
        val webSocket = webSocketHandles[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection state not found: $connectionId")

        if (connection.status != "connected") {
            return buildErrorJson("Connection is not active: status=${connection.status}")
        }

        webSocket.sendTextMessage(message)

        // Track outgoing message
        val index = messageIndexCounters[connectionId]?.getAndIncrement() ?: 0
        connection.messagesSent.incrementAndGet()

        val wsMessage = WebSocketMessage(
            index = index,
            direction = "client_to_server",
            type = "TEXT",
            payload = message,
            length = message.toByteArray().size,
            timestamp = Instant.now().toString()
        )
        connection.record(wsMessage)

        // Emit message event
        eventBus.emit("websocket.message", buildJsonObject {
            put("connection_id", connectionId)
            put("direction", "client_to_server")
            put("type", "TEXT")
            put("index", index)
            put("length", message.length)
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", "sent")
            put("type", "TEXT")
            put("message_index", index)
            put("length", message.length)
        }
    }

    /**
     * Sends a binary message on an existing WebSocket connection.
     *
     * @param connectionId The connection ID to send on.
     * @param data Base64-encoded binary data to send.
     * @return JSON object confirming the message was sent.
     */
    fun sendBinary(connectionId: String, data: String): JsonObject {
        val webSocket = webSocketHandles[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection state not found: $connectionId")

        if (connection.status != "connected") {
            return buildErrorJson("Connection is not active: status=${connection.status}")
        }

        val decodedBytes = Base64.getDecoder().decode(data)
        webSocket.sendBinaryMessage(BurpByteArray.byteArray(*decodedBytes))

        // Track outgoing message
        val index = messageIndexCounters[connectionId]?.getAndIncrement() ?: 0
        connection.messagesSent.incrementAndGet()

        val wsMessage = WebSocketMessage(
            index = index,
            direction = "client_to_server",
            type = "BINARY",
            payload = data,
            length = decodedBytes.size,
            timestamp = Instant.now().toString()
        )
        connection.record(wsMessage)

        // Emit message event
        eventBus.emit("websocket.message", buildJsonObject {
            put("connection_id", connectionId)
            put("direction", "client_to_server")
            put("type", "BINARY")
            put("index", index)
            put("length", decodedBytes.size)
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", "sent")
            put("type", "BINARY")
            put("message_index", index)
            put("length", decodedBytes.size)
        }
    }

    /**
     * Closes an existing WebSocket connection and updates its state.
     *
     * @param connectionId The connection ID to close.
     * @return JSON object confirming the closure.
     */
    fun close(connectionId: String): JsonObject {
        val webSocket = webSocketHandles.remove(connectionId)
            ?: return buildErrorJson("Connection not found: $connectionId")

        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection state not found: $connectionId")

        webSocket.close()
        connection.status = "closed"
        messageIndexCounters.remove(connectionId)

        // Emit close event
        eventBus.emit("websocket.closed", buildJsonObject {
            put("connection_id", connectionId)
            put("url", connection.url)
            put("messages_sent", connection.messagesSent.get())
            put("messages_received", connection.messagesReceived.get())
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("connection_id", connectionId)
            put("status", "closed")
            put("messages_sent", connection.messagesSent.get())
            put("messages_received", connection.messagesReceived.get())
        }
    }

    /**
     * Lists all WebSocket connections currently tracked in the StateManager.
     *
     * @return JSON object containing an array of connection summaries.
     */
    fun listConnections(): JsonObject {
        val connections = stateManager.websocketConnections.values.toList()
        return buildJsonObject {
            put("total_connections", connections.size)
            putJsonArray("connections") {
                for (conn in connections) {
                    addJsonObject {
                        put("connection_id", conn.connectionId)
                        put("url", conn.url)
                        put("status", conn.status)
                        put("created_at", conn.createdAt)
                        put("messages_sent", conn.messagesSent.get())
                        put("messages_received", conn.messagesReceived.get())
                        put("total_messages", conn.messages.size)
                    }
                }
            }
        }
    }

    /**
     * Retrieves messages from a specific WebSocket connection with optional
     * filtering by direction and pagination support.
     *
     * @param connectionId The connection to retrieve messages from.
     * @param direction Optional direction filter: "client_to_server", "server_to_client", or null for all.
     * @param sinceIndex Only return messages with index greater than this value.
     * @param maxResults Maximum number of messages to return.
     * @return JSON object containing the matching messages.
     */
    fun getMessages(
        connectionId: String,
        direction: String?,
        sinceIndex: Long,
        maxResults: Int
    ): JsonObject {
        val connection = stateManager.websocketConnections[connectionId]
            ?: return buildErrorJson("Connection not found: $connectionId")

        val messages = connection.messages.toList()

        val filtered = messages
            .filter { it.index > sinceIndex }
            .filter { msg -> direction == null || msg.direction == direction }
            .take(maxResults)

        return buildJsonObject {
            put("connection_id", connectionId)
            put("total_messages", messages.size)
            put("returned_messages", filtered.size)
            putJsonArray("messages") {
                for (msg in filtered) {
                    addJsonObject {
                        put("index", msg.index)
                        put("direction", msg.direction)
                        put("type", msg.type)
                        put("payload", msg.payload)
                        put("length", msg.length)
                        put("timestamp", msg.timestamp)
                    }
                }
            }
        }
    }

    /**
     * Creates a WebSocketCreatedHandler that monitors all WebSocket connections
     * initiated through Burp's proxy (or any other Burp component). Each new
     * connection is tracked in StateManager and emits lifecycle events.
     *
     * @return A WebSocketCreatedHandler to register with the Montoya API.
     */
    fun createWebSocketHandler(): WebSocketCreatedHandler {
        return WebSocketCreatedHandler { webSocketCreated: WebSocketCreated ->
            val connectionId = stateManager.generateId("ws")
            val upgradeRequest = webSocketCreated.upgradeRequest()
            val url = upgradeRequest.url()

            // Initialize per-connection state
            messageIndexCounters[connectionId] = AtomicLong(0)

            val connection = WebSocketConnection(
                connectionId = connectionId,
                url = url,
                createdAt = Instant.now().toString(),
                status = "connected"
            )
            stateManager.websocketConnections[connectionId] = connection

            // Emit creation event
            eventBus.emit("websocket.created", buildJsonObject {
                put("connection_id", connectionId)
                put("url", url)
                put("source", "proxy")
                put("timestamp", Instant.now().toString())
            })

            // Register a unified MessageHandler on the proxy WebSocket
            val proxyWs = webSocketCreated.webSocket()
            proxyWs.registerMessageHandler(object : MessageHandler {
                override fun handleTextMessage(textMessage: TextMessage): TextMessageAction {
                    val direction = when (textMessage.direction()) {
                        Direction.CLIENT_TO_SERVER -> "client_to_server"
                        Direction.SERVER_TO_CLIENT -> "server_to_client"
                        else -> "unknown"
                    }

                    val index = messageIndexCounters[connectionId]?.getAndIncrement() ?: 0

                    if (direction == "server_to_client") {
                        connection.messagesReceived.incrementAndGet()
                    } else {
                        connection.messagesSent.incrementAndGet()
                    }

                    val payload = textMessage.payload()
                    val wsMessage = WebSocketMessage(
                        index = index,
                        direction = direction,
                        type = "TEXT",
                        payload = payload,
                        length = payload.toByteArray().size,
                        timestamp = Instant.now().toString()
                    )
                    connection.record(wsMessage)

                    // Emit message event
                    eventBus.emit("websocket.message", buildJsonObject {
                        put("connection_id", connectionId)
                        put("direction", direction)
                        put("type", "TEXT")
                        put("index", index)
                        put("length", payload.length)
                        put("timestamp", Instant.now().toString())
                    })

                    // Apply intercept rules: drop, modify, or pass through.
                    return when (val outcome = evaluateTextRules(url, direction, payload)) {
                        is TextRuleOutcome.Drop -> TextMessageAction.drop()
                        is TextRuleOutcome.Modify -> TextMessageAction.continueWith(outcome.payload)
                        is TextRuleOutcome.Continue -> TextMessageAction.continueWith(textMessage)
                    }
                }

                override fun handleBinaryMessage(binaryMessage: BinaryMessage): BinaryMessageAction {
                    val direction = when (binaryMessage.direction()) {
                        Direction.CLIENT_TO_SERVER -> "client_to_server"
                        Direction.SERVER_TO_CLIENT -> "server_to_client"
                        else -> "unknown"
                    }

                    val index = messageIndexCounters[connectionId]?.getAndIncrement() ?: 0

                    if (direction == "server_to_client") {
                        connection.messagesReceived.incrementAndGet()
                    } else {
                        connection.messagesSent.incrementAndGet()
                    }

                    val rawBytes = binaryMessage.payload().getBytes()
                    val base64Payload = Base64.getEncoder().encodeToString(rawBytes)
                    val wsMessage = WebSocketMessage(
                        index = index,
                        direction = direction,
                        type = "BINARY",
                        payload = base64Payload,
                        length = rawBytes.size,
                        timestamp = Instant.now().toString()
                    )
                    connection.record(wsMessage)

                    // Emit message event
                    eventBus.emit("websocket.message", buildJsonObject {
                        put("connection_id", connectionId)
                        put("direction", direction)
                        put("type", "BINARY")
                        put("index", index)
                        put("length", rawBytes.size)
                        put("timestamp", Instant.now().toString())
                    })

                    // Apply intercept rules: binary supports drop / passthrough only.
                    return if (shouldDropBinary(url, direction)) {
                        BinaryMessageAction.drop()
                    } else {
                        BinaryMessageAction.continueWith(binaryMessage)
                    }
                }

                override fun onClose() {
                    connection.status = "closed"
                    messageIndexCounters.remove(connectionId)

                    eventBus.emit("websocket.closed", buildJsonObject {
                        put("connection_id", connectionId)
                        put("url", url)
                        put("messages_sent", connection.messagesSent.get())
                        put("messages_received", connection.messagesReceived.get())
                        put("timestamp", Instant.now().toString())
                    })
                }
            })
        }
    }

    /**
     * Creates or updates a WebSocket message interception rule. Rules are
     * evaluated by the WebSocket handler to modify, drop, or tag messages
     * matching specified criteria.
     *
     * @param ruleId Unique identifier for the rule.
     * @param matchUrl Optional URL regex to match against the WebSocket URL.
     * @param matchMessage Optional regex to match against message content.
     * @param direction Direction filter: "client_to_server", "server_to_client", or "both".
     * @param action What to do: "modify", "drop", or "tag".
     * @param modifyRegex Regex for message content replacement.
     * @param modifyReplacement Replacement string for regex matches.
     * @param tagComment Comment to attach to the matched message.
     * @param enabled Whether this rule is active.
     * @return JSON object confirming the rule was set.
     */
    fun setInterceptRule(
        ruleId: String?,
        matchUrl: String?,
        matchMessage: String?,
        direction: String,
        action: String,
        modifyRegex: String?,
        modifyReplacement: String?,
        tagComment: String?,
        enabled: Boolean
    ): JsonObject {
        val actualRuleId = ruleId ?: stateManager.generateId("wsrule")

        val rule = WebSocketInterceptRule(
            ruleId = actualRuleId,
            matchUrl = matchUrl,
            matchMessage = matchMessage,
            direction = direction,
            action = action,
            modifyRegex = modifyRegex,
            modifyReplacement = modifyReplacement,
            tagComment = tagComment,
            enabled = enabled
        )

        // Replace existing rule with same ID, or add new
        stateManager.websocketInterceptRules.removeIf { it.ruleId == actualRuleId }
        stateManager.websocketInterceptRules.add(rule)

        // Emit rule change event
        eventBus.emit("websocket.rule_set", buildJsonObject {
            put("rule_id", actualRuleId)
            put("action", action)
            put("direction", direction)
            put("enabled", enabled)
            put("timestamp", Instant.now().toString())
        })

        return buildJsonObject {
            put("rule_id", actualRuleId)
            put("status", "rule_set")
            put("action", action)
            put("direction", direction)
            put("enabled", enabled)
            put("total_rules", stateManager.websocketInterceptRules.size)
        }
    }

    /**
     * Registers message handlers on a programmatically created ExtensionWebSocket
     * to capture incoming messages from the server.
     */
    private fun registerExtensionMessageHandlers(webSocket: ExtensionWebSocket, connectionId: String) {
        val connection = stateManager.websocketConnections[connectionId] ?: return

        webSocket.registerMessageHandler(object : ExtensionWebSocketMessageHandler {
            override fun textMessageReceived(textMessage: TextMessage) {
                val index = messageIndexCounters[connectionId]?.getAndIncrement() ?: 0
                connection.messagesReceived.incrementAndGet()

                val payload = textMessage.payload()
                val wsMessage = WebSocketMessage(
                    index = index,
                    direction = "server_to_client",
                    type = "TEXT",
                    payload = payload,
                    length = payload.toByteArray().size,
                    timestamp = Instant.now().toString()
                )
                connection.record(wsMessage)

                eventBus.emit("websocket.message", buildJsonObject {
                    put("connection_id", connectionId)
                    put("direction", "server_to_client")
                    put("type", "TEXT")
                    put("index", index)
                    put("length", payload.length)
                    put("timestamp", Instant.now().toString())
                })

                // Evaluate intercept rules. This is a receive-only callback
                // (ExtensionWebSocketMessageHandler.textMessageReceived returns
                // void), so the Montoya API cannot drop or rewrite the frame
                // here. "tag" rules are honoured via their emitted event; for
                // "drop"/"modify" matches we surface an advisory event so the
                // rule is observable even though it cannot be enforced on this
                // path.
                applyIncomingRulesAdvisory(connection.url, "server_to_client", payload)
            }

            override fun binaryMessageReceived(binaryMessage: BinaryMessage) {
                val index = messageIndexCounters[connectionId]?.getAndIncrement() ?: 0
                connection.messagesReceived.incrementAndGet()

                val rawBytes = binaryMessage.payload().getBytes()
                val base64Payload = Base64.getEncoder().encodeToString(rawBytes)
                val wsMessage = WebSocketMessage(
                    index = index,
                    direction = "server_to_client",
                    type = "BINARY",
                    payload = base64Payload,
                    length = rawBytes.size,
                    timestamp = Instant.now().toString()
                )
                connection.record(wsMessage)

                eventBus.emit("websocket.message", buildJsonObject {
                    put("connection_id", connectionId)
                    put("direction", "server_to_client")
                    put("type", "BINARY")
                    put("index", index)
                    put("length", rawBytes.size)
                    put("timestamp", Instant.now().toString())
                })

                // Receive-only callback: honour "tag" rules and surface an
                // advisory event for unenforceable drop matches (see the text
                // handler above for rationale). Binary content is not matched
                // against matchMessage.
                applyIncomingBinaryRulesAdvisory(connection.url, "server_to_client")
            }

            override fun onClose() {
                connection.status = "closed"
                webSocketHandles.remove(connectionId)
                messageIndexCounters.remove(connectionId)

                eventBus.emit("websocket.closed", buildJsonObject {
                    put("connection_id", connectionId)
                    put("url", connection.url)
                    put("messages_sent", connection.messagesSent.get())
                    put("messages_received", connection.messagesReceived.get())
                    put("timestamp", Instant.now().toString())
                })
            }
        })
    }

    /**
     * The outcome of evaluating intercept rules against a text message.
     *
     * - [Continue]: forward the message unchanged.
     * - [Drop]: discard the message entirely.
     * - [Modify]: forward the message with [payload] substituted as the new text.
     */
    private sealed class TextRuleOutcome {
        object Continue : TextRuleOutcome()
        object Drop : TextRuleOutcome()
        data class Modify(val payload: String) : TextRuleOutcome()
    }

    /**
     * Returns true if [rule] applies to a message with the given [url] and
     * [direction] ("client_to_server" / "server_to_client"), and whose textual
     * [content] satisfies the rule's matchMessage pattern.
     *
     * Null match fields mean "match any". A rule direction of "both" matches
     * either direction. Regex compilation failures are treated as non-matches so
     * a malformed pattern can never crash the message handler.
     */
    private fun ruleMatches(
        rule: WebSocketInterceptRule,
        url: String?,
        direction: String,
        content: String
    ): Boolean {
        // Direction filter ("both" or matching the message direction).
        if (rule.direction != "both" && rule.direction != direction) {
            return false
        }

        // URL filter (regex against the connection URL, if one is available).
        rule.matchUrl?.let { pattern ->
            val target = url ?: return false
            val matched = try {
                Regex(pattern).containsMatchIn(target)
            } catch (e: Exception) {
                false
            }
            if (!matched) return false
        }

        // Message-content filter (regex against the text payload).
        rule.matchMessage?.let { pattern ->
            val matched = try {
                Regex(pattern).containsMatchIn(content)
            } catch (e: Exception) {
                false
            }
            if (!matched) return false
        }

        return true
    }

    /**
     * Evaluates all enabled intercept rules against a text message and returns
     * the resulting action. The first matching "drop" wins; otherwise "modify"
     * rules are applied in order to the payload, and "tag" rules emit an event.
     *
     * @param url The WebSocket connection URL, or null if unknown.
     * @param direction "client_to_server" or "server_to_client".
     * @param payload The original text payload.
     * @return A [TextRuleOutcome] describing what the caller should do.
     */
    private fun evaluateTextRules(
        url: String?,
        direction: String,
        payload: String
    ): TextRuleOutcome {
        var current = payload
        var modified = false

        for (rule in stateManager.websocketInterceptRules.toList()) {
            if (!rule.enabled) continue
            if (!ruleMatches(rule, url, direction, current)) continue

            when (rule.action) {
                "drop" -> return TextRuleOutcome.Drop

                "modify" -> {
                    val regex = rule.modifyRegex
                    val replacement = rule.modifyReplacement ?: ""
                    if (regex != null) {
                        try {
                            current = Regex(regex).replace(current, replacement)
                            modified = true
                        } catch (e: Exception) {
                            // Bad pattern: skip this rule, keep processing others.
                        }
                    }
                }

                "tag" -> {
                    eventBus.emit("websocket.message_tagged", buildJsonObject {
                        put("rule_id", rule.ruleId)
                        put("direction", direction)
                        if (url != null) put("url", url)
                        if (rule.tagComment != null) put("comment", rule.tagComment)
                        put("timestamp", Instant.now().toString())
                    })
                }
            }
        }

        return if (modified) TextRuleOutcome.Modify(current) else TextRuleOutcome.Continue
    }

    /**
     * Evaluates enabled intercept rules against a binary message. Binary payloads
     * cannot be regex-modified, so only "drop" (and "tag", which emits an event)
     * are honoured; everything else passes through unchanged.
     *
     * Rules that carry a matchMessage pattern are skipped for binary frames since
     * there is no meaningful text content to match against.
     *
     * @param url The WebSocket connection URL, or null if unknown.
     * @param direction "client_to_server" or "server_to_client".
     * @return true if the binary message should be dropped, false to continue.
     */
    private fun shouldDropBinary(url: String?, direction: String): Boolean {
        for (rule in stateManager.websocketInterceptRules.toList()) {
            if (!rule.enabled) continue
            // Binary frames have no text content; matchMessage cannot apply.
            if (rule.matchMessage != null) continue
            if (!ruleMatches(rule, url, direction, "")) continue

            when (rule.action) {
                "drop" -> return true
                "tag" -> {
                    eventBus.emit("websocket.message_tagged", buildJsonObject {
                        put("rule_id", rule.ruleId)
                        put("direction", direction)
                        put("type", "BINARY")
                        if (url != null) put("url", url)
                        if (rule.tagComment != null) put("comment", rule.tagComment)
                        put("timestamp", Instant.now().toString())
                    })
                }
                // "modify" is not supported for binary frames; pass through.
            }
        }
        return false
    }

    /**
     * Applies intercept rules to an incoming text frame received on a
     * programmatically created ExtensionWebSocket. Because that callback is
     * receive-only (returns void), drop/modify cannot be enforced by the API;
     * "tag" rules are fully honoured (they emit their own event), and any
     * matching drop/modify rule produces an advisory event so it remains
     * observable.
     */
    private fun applyIncomingRulesAdvisory(url: String?, direction: String, payload: String) {
        when (evaluateTextRules(url, direction, payload)) {
            is TextRuleOutcome.Drop -> eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
                put("direction", direction)
                put("action", "drop")
                put("reason", "extension_websocket_receive_only")
                if (url != null) put("url", url)
                put("timestamp", Instant.now().toString())
            })
            is TextRuleOutcome.Modify -> eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
                put("direction", direction)
                put("action", "modify")
                put("reason", "extension_websocket_receive_only")
                if (url != null) put("url", url)
                put("timestamp", Instant.now().toString())
            })
            is TextRuleOutcome.Continue -> { /* nothing to do */ }
        }
    }

    /**
     * Binary-frame counterpart to [applyIncomingRulesAdvisory]. Honours "tag"
     * rules and emits an advisory event when a drop rule matches but cannot be
     * enforced on the receive-only extension callback.
     */
    private fun applyIncomingBinaryRulesAdvisory(url: String?, direction: String) {
        if (shouldDropBinary(url, direction)) {
            eventBus.emit("websocket.rule_unenforceable", buildJsonObject {
                put("direction", direction)
                put("action", "drop")
                put("type", "BINARY")
                put("reason", "extension_websocket_receive_only")
                if (url != null) put("url", url)
                put("timestamp", Instant.now().toString())
            })
        }
    }

    /**
     * Generates a random Sec-WebSocket-Key for the upgrade request.
     */
    private fun generateWebSocketKey(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }

    /**
     * Builds a standardized error JSON object.
     */
    private fun buildErrorJson(message: String): JsonObject {
        return buildJsonObject {
            put("error", message)
        }
    }
}
