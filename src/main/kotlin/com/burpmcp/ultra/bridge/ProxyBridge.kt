package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHistoryFilter
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.websocket.Direction
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.safety.HeaderSafety
import com.burpmcp.ultra.safety.SafeRegex
import com.burpmcp.ultra.state.ProxyRule
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.regex.Pattern

/**
 * Bridge wrapping the Montoya Proxy API.
 *
 * Provides MCP-friendly methods for reading proxy history, controlling
 * interception, annotating items, and managing proxy rules. Also creates
 * the [ProxyRequestHandler] and [ProxyResponseHandler] registered during
 * extension initialization.
 */
class ProxyBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {

    // ---------------------------------------------------------------
    // History retrieval
    // ---------------------------------------------------------------

    /**
     * Returns a slice of the HTTP proxy history with optional filtering.
     *
     * @param startIndex Zero-based offset into the filtered history.
     * @param count Maximum number of items to return.
     * @param host Optional hostname filter (case-insensitive substring match).
     * @param method Optional HTTP method filter (exact, case-insensitive).
     * @param statusCode Optional exact status code filter.
     * @param mimeType Optional MIME type filter (case-insensitive name match).
     * @param inScopeOnly When true, only return in-scope items.
     * @param includeRequest Whether to include the full request text.
     * @param includeResponse Whether to include the full response text.
     * @param statusCodeRange Optional "min-max" range string for status codes.
     * @return JSON object with total count, returned count, and items array.
     */
    fun getHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        method: String?,
        statusCode: Int?,
        mimeType: String?,
        inScopeOnly: Boolean,
        includeRequest: Boolean = false,
        includeResponse: Boolean = false,
        statusCodeRange: String? = null,
        maxResponseLength: Int? = null
    ): JsonObject {
        // Resolve the optional MIME type filter up front so an unrecognized value
        // produces a clear error instead of silently dropping the filter (which
        // would return ALL history as if it matched).
        val resolvedMimeType: MimeType? = if (mimeType != null) {
            resolveMimeType(mimeType)
                ?: return buildJsonObject {
                    put(
                        "error",
                        "Unknown mime_type: $mimeType. Valid values: ${mimeTypeValidValues()}"
                    )
                }
        } else {
            null
        }

        val filter = ProxyHistoryFilter { item ->
            if (inScopeOnly && !item.request().isInScope()) return@ProxyHistoryFilter false
            if (host != null && !item.host().contains(host, ignoreCase = true)) return@ProxyHistoryFilter false
            if (method != null && !item.method().equals(method, ignoreCase = true)) return@ProxyHistoryFilter false
            if (statusCode != null && item.hasResponse()) {
                if (item.response().statusCode().toInt() != statusCode) return@ProxyHistoryFilter false
            }
            if (statusCodeRange != null && item.hasResponse()) {
                val parts = statusCodeRange.split("-")
                if (parts.size == 2) {
                    val min = parts[0].trim().toIntOrNull() ?: 0
                    val max = parts[1].trim().toIntOrNull() ?: 999
                    val sc = item.response().statusCode().toInt()
                    if (sc < min || sc > max) return@ProxyHistoryFilter false
                }
            }
            if (resolvedMimeType != null && item.mimeType() != resolvedMimeType) {
                return@ProxyHistoryFilter false
            }
            true
        }

        val allItems = api.proxy().history(filter)
        val totalFiltered = allItems.size
        val slice = allItems.drop(startIndex).take(count.coerceIn(0, 1000))

        return buildJsonObject {
            put("total_filtered", totalFiltered)
            put("start_index", startIndex)
            put("returned", slice.size)
            put("items", buildJsonArray {
                slice.forEach { item ->
                    add(serializeHistoryItem(item, includeRequest, includeResponse, maxResponseLength ?: 200_000))
                }
            })
        }
    }

    /**
     * Searches proxy history using a regex pattern.
     *
     * @param pattern Regex pattern to match.
     * @param searchIn Where to search: "request", "response", or "both".
     * @param caseSensitive Whether the regex is case-sensitive.
     * @param maxResults Maximum number of matching items to return.
     * @param inScopeOnly When true, only search in-scope items.
     * @param includeRequest Whether to include the full request text.
     * @param includeResponse Whether to include the full response text.
     * @return JSON object with match count and items array.
     */
    fun searchHistory(
        pattern: String,
        searchIn: String,
        caseSensitive: Boolean,
        maxResults: Int,
        inScopeOnly: Boolean,
        includeRequest: Boolean = false,
        includeResponse: Boolean = false,
        maxResponseLength: Int? = null
    ): JsonObject {
        val flags = if (caseSensitive) 0 else Pattern.CASE_INSENSITIVE
        val compiledPattern = Pattern.compile(pattern, flags)

        val filter = ProxyHistoryFilter { item ->
            if (inScopeOnly && !item.request().isInScope()) return@ProxyHistoryFilter false

            val searchRequest = searchIn.equals("request", ignoreCase = true) ||
                searchIn.equals("both", ignoreCase = true)
            val searchResponse = searchIn.equals("response", ignoreCase = true) ||
                searchIn.equals("both", ignoreCase = true)

            var found = false
            if (searchRequest) {
                // Match against the request only. item.contains(pattern) inherits
                // HttpRequestResponse.contains, which matches BOTH request and
                // response, so a request-only search must inspect the request text.
                found = compiledPattern.matcher(item.request().toString()).find()
            }
            if (!found && searchResponse && item.hasResponse()) {
                found = compiledPattern.matcher(item.response().toString()).find()
            }
            found
        }

        val matches = api.proxy().history(filter)
        val limited = matches.take(maxResults.coerceIn(0, 1000))

        return buildJsonObject {
            put("total_matches", matches.size)
            put("returned", limited.size)
            put("pattern", pattern)
            put("search_in", searchIn)
            put("items", buildJsonArray {
                limited.forEach { item ->
                    add(serializeHistoryItem(item, includeRequest, includeResponse, maxResponseLength ?: 200_000))
                }
            })
        }
    }

    /**
     * Returns WebSocket proxy history with optional filtering.
     *
     * @param startIndex Zero-based offset.
     * @param count Maximum number of items.
     * @param host Optional hostname filter.
     * @param direction Optional direction filter: "CLIENT_TO_SERVER" or "SERVER_TO_CLIENT".
     * @return JSON object with items array.
     */
    fun getWebSocketHistory(
        startIndex: Int,
        count: Int,
        host: String?,
        direction: String?
    ): JsonObject {
        val dirFilter = direction?.let {
            try { Direction.valueOf(it.uppercase()) } catch (_: Exception) { null }
        }

        val filter = ProxyWebSocketHistoryFilter { item ->
            if (host != null) {
                val upgradeHost = try { item.upgradeRequest()?.httpService()?.host() } catch (_: Exception) { null }
                if (upgradeHost != null && !upgradeHost.contains(host, ignoreCase = true)) {
                    return@ProxyWebSocketHistoryFilter false
                }
            }
            if (dirFilter != null && item.direction() != dirFilter) {
                return@ProxyWebSocketHistoryFilter false
            }
            true
        }

        val allItems = api.proxy().webSocketHistory(filter)
        val totalFiltered = allItems.size
        val slice = allItems.drop(startIndex).take(count.coerceIn(0, 1000))

        return buildJsonObject {
            put("total_filtered", totalFiltered)
            put("start_index", startIndex)
            put("returned", slice.size)
            put("items", buildJsonArray {
                slice.forEach { item -> add(serializeWebSocketItem(item)) }
            })
        }
    }

    /**
     * Searches WebSocket proxy history using a regex pattern on message payloads.
     *
     * @param pattern Regex pattern.
     * @param direction Optional direction filter.
     * @param maxResults Maximum results.
     * @return JSON object with match results.
     */
    fun searchWebSocketHistory(
        pattern: String,
        direction: String?,
        maxResults: Int
    ): JsonObject {
        val compiledPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE)
        val dirFilter = direction?.let {
            try { Direction.valueOf(it.uppercase()) } catch (_: Exception) { null }
        }

        val filter = ProxyWebSocketHistoryFilter { item ->
            if (dirFilter != null && item.direction() != dirFilter) return@ProxyWebSocketHistoryFilter false
            item.contains(compiledPattern)
        }

        val matches = api.proxy().webSocketHistory(filter)
        val limited = matches.take(maxResults.coerceIn(0, 1000))

        return buildJsonObject {
            put("total_matches", matches.size)
            put("returned", limited.size)
            put("pattern", pattern)
            put("items", buildJsonArray {
                limited.forEach { item -> add(serializeWebSocketItem(item)) }
            })
        }
    }

    // ---------------------------------------------------------------
    // Intercept control
    // ---------------------------------------------------------------

    /** Enables proxy interception. */
    fun enableIntercept(): JsonObject {
        api.proxy().enableIntercept()
        eventBus.emit("proxy.intercept", buildJsonObject {
            put("enabled", true)
            put("timestamp", Instant.now().toString())
        })
        return buildJsonObject { put("intercept_enabled", true) }
    }

    /** Disables proxy interception. */
    fun disableIntercept(): JsonObject {
        api.proxy().disableIntercept()
        eventBus.emit("proxy.intercept", buildJsonObject {
            put("enabled", false)
            put("timestamp", Instant.now().toString())
        })
        return buildJsonObject { put("intercept_enabled", false) }
    }

    /** Returns the current intercept state. */
    fun isInterceptEnabled(): JsonObject {
        return buildJsonObject {
            put("intercept_enabled", api.proxy().isInterceptEnabled)
        }
    }

    // ---------------------------------------------------------------
    // Annotation
    // ---------------------------------------------------------------

    /**
     * Annotates a proxy history item by its index (message ID).
     *
     * @param index The proxy history item message ID.
     * @param comment Optional comment to set.
     * @param highlight Optional highlight color name (e.g., "RED", "BLUE").
     * @return JSON object confirming the annotation.
     */
    fun annotateHistoryItem(index: Int, comment: String?, highlight: String?): JsonObject {
        val history = api.proxy().history()
        val item = history.find { it.id() == index }
            ?: return buildJsonObject {
                put("error", "History item with id $index not found")
            }

        val annotations = item.annotations()
        if (comment != null) {
            annotations.setNotes(comment)
        }
        if (highlight != null) {
            val color = try {
                HighlightColor.highlightColor(highlight)
            } catch (_: Exception) {
                try { HighlightColor.valueOf(highlight.uppercase()) } catch (_: Exception) { null }
            }
            if (color != null) {
                annotations.setHighlightColor(color)
            }
        }

        return buildJsonObject {
            put("index", index)
            put("annotated", true)
            if (comment != null) put("comment", comment)
            if (highlight != null) put("highlight", highlight)
        }
    }

    // ---------------------------------------------------------------
    // Proxy handlers (registered during extension init)
    // ---------------------------------------------------------------

    /**
     * Creates a [ProxyRequestHandler] that:
     * 1. Evaluates proxy rules from [StateManager.proxyRules] against each request.
     * 2. Applies matching rule actions (modify, drop, tag).
     * 3. Emits "proxy.request" events to the [EventBus].
     */
    fun createRequestHandler(): ProxyRequestHandler {
        return object : ProxyRequestHandler {
            override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
                // Emit event for every request passing through the proxy
                emitRequestEvent(interceptedRequest)

                // Find matching request rules
                val matchingRules = stateManager.proxyRules.filter { rule ->
                    rule.enabled && rule.type.equals("request", ignoreCase = true) &&
                        matchesRequestRule(rule, interceptedRequest)
                }

                if (matchingRules.isEmpty()) {
                    return ProxyRequestReceivedAction.continueWith(interceptedRequest)
                }

                var currentRequest: HttpRequest = interceptedRequest
                var currentAnnotations = interceptedRequest.annotations()
                var shouldDrop = false

                for (rule in matchingRules) {
                    when (rule.action.lowercase()) {
                        "drop" -> {
                            shouldDrop = true
                            eventBus.emit("proxy.rule.applied", buildJsonObject {
                                put("rule_id", rule.ruleId)
                                put("action", "drop")
                                put("url", interceptedRequest.url())
                                put("timestamp", Instant.now().toString())
                            })
                            break
                        }
                        "modify" -> {
                            currentRequest = applyRequestModifications(rule, currentRequest)
                            eventBus.emit("proxy.rule.applied", buildJsonObject {
                                put("rule_id", rule.ruleId)
                                put("action", "modify")
                                put("url", interceptedRequest.url())
                                put("timestamp", Instant.now().toString())
                            })
                        }
                        "tag" -> {
                            if (rule.tagComment != null) {
                                currentAnnotations = currentAnnotations.withNotes(rule.tagComment)
                            }
                            if (rule.tagHighlight != null) {
                                val color = resolveHighlightColor(rule.tagHighlight)
                                if (color != null) {
                                    currentAnnotations = currentAnnotations.withHighlightColor(color)
                                }
                            }
                            eventBus.emit("proxy.rule.applied", buildJsonObject {
                                put("rule_id", rule.ruleId)
                                put("action", "tag")
                                put("url", interceptedRequest.url())
                                put("timestamp", Instant.now().toString())
                            })
                        }
                    }
                }

                return if (shouldDrop) {
                    ProxyRequestReceivedAction.drop()
                } else {
                    ProxyRequestReceivedAction.continueWith(currentRequest, currentAnnotations)
                }
            }

            override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
            }
        }
    }

    /**
     * Creates a [ProxyResponseHandler] that:
     * 1. Evaluates proxy rules from [StateManager.proxyRules] against each response.
     * 2. Applies matching rule actions (modify, drop, tag).
     * 3. Emits "proxy.response" events to the [EventBus].
     */
    fun createResponseHandler(): ProxyResponseHandler {
        return object : ProxyResponseHandler {
            override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
                // Emit event for every response passing through the proxy
                emitResponseEvent(interceptedResponse)

                // Find matching response rules
                val matchingRules = stateManager.proxyRules.filter { rule ->
                    rule.enabled && rule.type.equals("response", ignoreCase = true) &&
                        matchesResponseRule(rule, interceptedResponse)
                }

                if (matchingRules.isEmpty()) {
                    return ProxyResponseReceivedAction.continueWith(interceptedResponse)
                }

                var currentResponse: HttpResponse = interceptedResponse
                var currentAnnotations = interceptedResponse.annotations()
                var shouldDrop = false

                for (rule in matchingRules) {
                    when (rule.action.lowercase()) {
                        "drop" -> {
                            shouldDrop = true
                            eventBus.emit("proxy.rule.applied", buildJsonObject {
                                put("rule_id", rule.ruleId)
                                put("action", "drop")
                                put("url", interceptedResponse.request()?.url() ?: "")
                                put("timestamp", Instant.now().toString())
                            })
                            break
                        }
                        "modify" -> {
                            currentResponse = applyResponseModifications(rule, currentResponse)
                            eventBus.emit("proxy.rule.applied", buildJsonObject {
                                put("rule_id", rule.ruleId)
                                put("action", "modify")
                                put("url", interceptedResponse.request()?.url() ?: "")
                                put("timestamp", Instant.now().toString())
                            })
                        }
                        "tag" -> {
                            if (rule.tagComment != null) {
                                currentAnnotations = currentAnnotations.withNotes(rule.tagComment)
                            }
                            if (rule.tagHighlight != null) {
                                val color = resolveHighlightColor(rule.tagHighlight)
                                if (color != null) {
                                    currentAnnotations = currentAnnotations.withHighlightColor(color)
                                }
                            }
                            eventBus.emit("proxy.rule.applied", buildJsonObject {
                                put("rule_id", rule.ruleId)
                                put("action", "tag")
                                put("url", interceptedResponse.request()?.url() ?: "")
                                put("timestamp", Instant.now().toString())
                            })
                        }
                    }
                }

                return if (shouldDrop) {
                    ProxyResponseReceivedAction.drop()
                } else {
                    ProxyResponseReceivedAction.continueWith(currentResponse, currentAnnotations)
                }
            }

            override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
            }
        }
    }

    // ---------------------------------------------------------------
    // Rule matching helpers
    // ---------------------------------------------------------------

    /**
     * Tests whether a request matches a proxy rule's conditions.
     * All non-null conditions must match (logical AND).
     */
    private fun matchesRequestRule(rule: ProxyRule, request: InterceptedRequest): Boolean {
        if (rule.matchHost != null) {
            val hostPattern = rule.matchHost.replace("*", ".*")
            if (!SafeRegex.matches(hostPattern, request.httpService().host(), ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchUrl != null) {
            if (!SafeRegex.containsMatchIn(rule.matchUrl, request.url(), ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchMethod != null) {
            if (!request.method().equals(rule.matchMethod, ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchHeader != null) {
            val headerStr = request.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
            if (!SafeRegex.containsMatchIn(rule.matchHeader, headerStr, ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchBody != null) {
            val body = request.bodyToString()
            if (!SafeRegex.containsMatchIn(rule.matchBody, body, ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    /**
     * Tests whether a response matches a proxy rule's conditions.
     * All non-null conditions must match (logical AND).
     */
    private fun matchesResponseRule(rule: ProxyRule, response: InterceptedResponse): Boolean {
        if (rule.matchHost != null) {
            val host = try { response.request()?.httpService()?.host() } catch (_: Exception) { null }
            if (host != null) {
                val hostPattern = rule.matchHost.replace("*", ".*")
                if (!SafeRegex.matches(hostPattern, host, ignoreCase = true)) {
                    return false
                }
            }
        }
        if (rule.matchUrl != null) {
            val url = try { response.request()?.url() } catch (_: Exception) { null }
            if (url != null && !SafeRegex.containsMatchIn(rule.matchUrl, url, ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchStatus != null) {
            if (response.statusCode().toInt() != rule.matchStatus) {
                return false
            }
        }
        if (rule.matchHeader != null) {
            val headerStr = response.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
            if (!SafeRegex.containsMatchIn(rule.matchHeader, headerStr, ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchBody != null) {
            val body = response.bodyToString()
            if (!SafeRegex.containsMatchIn(rule.matchBody, body, ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    // ---------------------------------------------------------------
    // Modification helpers
    // ---------------------------------------------------------------

    /**
     * Applies a rule's modification directives to an HTTP request.
     * Returns a new (possibly modified) request; the original is not mutated.
     */
    private fun applyRequestModifications(rule: ProxyRule, request: HttpRequest): HttpRequest {
        var modified = request

        // Add header
        if (rule.modifyAddHeader != null) {
            HeaderSafety.parseHeaderLine(rule.modifyAddHeader)?.let { (name, value) ->
                modified = modified.withAddedHeader(name, value)
            }
        }

        // Remove header
        if (rule.modifyRemoveHeader != null) {
            modified = modified.withRemovedHeader(rule.modifyRemoveHeader)
        }

        // Replace headers
        rule.modifyReplaceHeader?.forEach { (headerName, headerValue) ->
            modified = modified.withUpdatedHeader(headerName, headerValue)
        }

        // Body regex replacement
        if (rule.modifyBodyRegex != null && rule.modifyBodyReplacement != null) {
            val body = modified.bodyToString()
            val newBody = SafeRegex.replace(rule.modifyBodyRegex, body, rule.modifyBodyReplacement, ignoreCase = true)
            modified = modified.withBody(newBody)
        }

        return modified
    }

    /**
     * Applies a rule's modification directives to an HTTP response.
     * Returns a new (possibly modified) response; the original is not mutated.
     */
    private fun applyResponseModifications(rule: ProxyRule, response: HttpResponse): HttpResponse {
        var modified = response

        // Add header
        if (rule.modifyAddHeader != null) {
            HeaderSafety.parseHeaderLine(rule.modifyAddHeader)?.let { (name, value) ->
                modified = modified.withAddedHeader(name, value)
            }
        }

        // Remove header
        if (rule.modifyRemoveHeader != null) {
            modified = modified.withRemovedHeader(rule.modifyRemoveHeader)
        }

        // Replace headers
        rule.modifyReplaceHeader?.forEach { (headerName, headerValue) ->
            modified = modified.withUpdatedHeader(headerName, headerValue)
        }

        // Body regex replacement
        if (rule.modifyBodyRegex != null && rule.modifyBodyReplacement != null) {
            val body = modified.bodyToString()
            val newBody = SafeRegex.replace(rule.modifyBodyRegex, body, rule.modifyBodyReplacement, ignoreCase = true)
            modified = modified.withBody(newBody)
        }

        return modified
    }

    // ---------------------------------------------------------------
    // Event emission helpers
    // ---------------------------------------------------------------

    private fun emitRequestEvent(request: InterceptedRequest) {
        eventBus.emit("proxy.request", buildJsonObject {
            put("message_id", request.messageId())
            put("method", request.method())
            put("url", request.url())
            put("host", request.httpService().host())
            put("port", request.httpService().port())
            put("secure", request.httpService().secure())
            put("in_scope", request.isInScope())
            put("timestamp", Instant.now().toString())
        })
    }

    private fun emitResponseEvent(response: InterceptedResponse) {
        eventBus.emit("proxy.response", buildJsonObject {
            put("message_id", response.messageId())
            put("status_code", response.statusCode().toInt())
            put("mime_type", response.mimeType().name)
            try {
                val req = response.request()
                if (req != null) {
                    put("url", req.url())
                    put("host", req.httpService().host())
                }
            } catch (_: Exception) {
                // request may not be available
            }
            put("timestamp", Instant.now().toString())
        })
    }

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    /**
     * Serializes a [ProxyHttpRequestResponse] to a [JsonObject].
     */
    private fun serializeHistoryItem(
        item: ProxyHttpRequestResponse,
        includeRequest: Boolean,
        includeResponse: Boolean,
        maxResponseLength: Int? = null
    ): JsonObject {
        return buildJsonObject {
            put("index", item.id())
            put("host", item.host())
            put("port", item.port())
            put("secure", item.secure())
            put("method", item.method())
            put("url", item.url())
            put("path", item.path())
            put("edited", item.edited())
            put("mime_type", item.mimeType().name)
            put("has_response", item.hasResponse())

            // Timing
            try {
                val time = item.time()
                if (time != null) put("time", time.toString())
            } catch (_: Exception) { }

            // Timing data
            try {
                val td = item.timingData()
                if (td != null) {
                    put("timing", buildJsonObject {
                        put("time_to_first_byte_ms", td.timeBetweenRequestSentAndStartOfResponse().toMillis())
                        put("time_to_complete_ms", td.timeBetweenRequestSentAndEndOfResponse().toMillis())
                    })
                }
            } catch (_: Exception) { }

            // Response metadata
            if (item.hasResponse()) {
                try {
                    val resp = item.response()
                    put("status_code", resp.statusCode().toInt())
                    put("response_length", resp.body().length())
                    put("response_mime_type", resp.mimeType().name)
                } catch (_: Exception) { }
            }

            // Annotations
            try {
                val ann = item.annotations()
                if (ann.hasNotes()) put("comment", ann.notes())
                if (ann.hasHighlightColor()) put("highlight", ann.highlightColor().name)
            } catch (_: Exception) { }

            // Request headers
            try {
                put("request_headers", buildJsonArray {
                    item.request().headers().forEach { h ->
                        add(buildJsonObject {
                            put("name", h.name())
                            put("value", h.value())
                        })
                    }
                })
            } catch (_: Exception) { }

            // Full request text
            if (includeRequest) {
                try {
                    put("request", item.request().toString())
                } catch (_: Exception) {
                    put("request", "")
                }
            }

            // Full response text
            if (includeResponse && item.hasResponse()) {
                try {
                    val respStr = item.response().toString()
                    val responseText = if (maxResponseLength != null && maxResponseLength > 0 && respStr.length > maxResponseLength) {
                        respStr.take(maxResponseLength) + "... [truncated, full length: ${respStr.length}]"
                    } else {
                        respStr
                    }
                    put("response", responseText)
                } catch (_: Exception) {
                    put("response", "")
                }
            }
        }
    }

    /**
     * Serializes a [ProxyWebSocketMessage] to a [JsonObject].
     */
    private fun serializeWebSocketItem(item: ProxyWebSocketMessage): JsonObject {
        return buildJsonObject {
            put("id", item.id())
            put("websocket_id", item.webSocketId())
            put("direction", item.direction().name)
            put("listener_port", item.listenerPort())

            try {
                val time = item.time()
                if (time != null) put("time", time.toString())
            } catch (_: Exception) { }

            try {
                val payload = item.payload()
                put("payload", payload.toString())
                put("payload_length", payload.length())
            } catch (_: Exception) {
                put("payload", "")
                put("payload_length", 0)
            }

            try {
                val editedPayload = item.editedPayload()
                if (editedPayload != null) {
                    put("edited_payload", editedPayload.toString())
                }
            } catch (_: Exception) { }

            try {
                val ann = item.annotations()
                if (ann.hasNotes()) put("comment", ann.notes())
                if (ann.hasHighlightColor()) put("highlight", ann.highlightColor().name)
            } catch (_: Exception) { }

            try {
                val upgradeReq = item.upgradeRequest()
                if (upgradeReq != null) {
                    put("upgrade_url", upgradeReq.url())
                    put("upgrade_host", upgradeReq.httpService().host())
                }
            } catch (_: Exception) { }
        }
    }

    /**
     * Resolves a caller-supplied MIME type string to a [MimeType] enum constant.
     *
     * Accepts both the Montoya enum constant names (e.g. "JSON", "HTML") and a
     * set of common content-type / alias spellings (e.g. "application/json",
     * "text/html", "javascript"). Returns null if it cannot be resolved.
     */
    private fun resolveMimeType(input: String): MimeType? {
        val normalized = input.trim()

        // Direct enum constant match (case-insensitive), e.g. "JSON", "PLAIN_TEXT".
        try {
            return MimeType.valueOf(normalized.uppercase())
        } catch (_: Exception) {
            // fall through to alias resolution
        }

        // Common content-type strings and short aliases mapped to enum constants.
        return when (normalized.lowercase()) {
            "application/json", "json", "text/json" -> MimeType.JSON
            "text/html", "html", "application/xhtml+xml", "xhtml" -> MimeType.HTML
            "text/plain", "plain", "text" -> MimeType.PLAIN_TEXT
            "text/css", "css" -> MimeType.CSS
            "application/javascript", "text/javascript", "javascript", "js", "script" -> MimeType.SCRIPT
            "application/xml", "text/xml", "xml" -> MimeType.XML
            "application/yaml", "text/yaml", "yaml", "yml" -> MimeType.YAML
            "text/event-stream", "sse" -> MimeType.SSE
            "application/rtf", "text/rtf", "rtf" -> MimeType.RTF
            else -> null
        }
    }

    /**
     * A human-readable hint listing the accepted MIME type values, for error messages.
     */
    private fun mimeTypeValidValues(): String {
        val constants = MimeType.values().joinToString(", ") { it.name }
        return "$constants (also accepts common aliases such as application/json, text/html, text/plain, application/javascript, application/xml)"
    }

    /**
     * Resolves a highlight color name to a [HighlightColor] enum value.
     * Tries the Montoya factory method first, then falls back to valueOf.
     */
    private fun resolveHighlightColor(name: String): HighlightColor? {
        return try {
            HighlightColor.highlightColor(name)
        } catch (_: Exception) {
            try { HighlightColor.valueOf(name.uppercase()) } catch (_: Exception) { null }
        }
    }
}
