package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.params.HttpParameter
import com.burpmcp.ultra.safety.HeaderSafety
import com.burpmcp.ultra.safety.SafeRegex
import com.burpmcp.ultra.safety.ScopeDecision
import com.burpmcp.ultra.safety.ScopeMode
import com.burpmcp.ultra.safety.ScopePolicy
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer
import burp.api.montoya.core.ByteArray as BurpByteArray
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.SessionRule
import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.state.TrafficRule
import com.burpmcp.ultra.transport.ToolCallTracker
import com.burpmcp.ultra.core.asBodyString
import com.burpmcp.ultra.core.asStringMap
import kotlinx.serialization.json.*
import java.net.URI
import java.time.Instant
import java.time.ZonedDateTime
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Bridge wrapping the Montoya HTTP API.
 *
 * Provides MCP-friendly methods for sending HTTP requests, managing cookies,
 * analyzing responses, and managing global traffic rules. Also creates the
 * [HttpHandler] registered during extension initialization.
 */
class HttpBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {

    /**
     * Adds an HttpRequestResponse to Burp's sitemap and annotates it as MCP-originated.
     * Called after every request sent via MCP tools so it's visible in Burp UI.
     */
    private fun addToSitemap(result: HttpRequestResponse, note: String = "[MCP] BurpMCP-Ultra") {
        try {
            api.siteMap().add(result)
        } catch (_: Exception) {}
        try {
            result.annotations().setNotes(note)
        } catch (_: Exception) {}
    }

    // ---------------------------------------------------------------
    // Send request
    // ---------------------------------------------------------------

    /**
     * Sends a single HTTP request and returns the serialized response.
     *
     * The request can be built from either a raw HTTP string or from
     * structured parameters (URL, method, headers, body).
     *
     * @param url Target URL (used when rawRequest is null).
     * @param method HTTP method (defaults to "GET").
     * @param headers Map of header name to value.
     * @param body Optional request body string.
     * @param rawRequest Optional raw HTTP request string (takes priority).
     * @param host Optional target host override.
     * @param port Optional target port override.
     * @param useTls Optional TLS flag override.
     * @param httpMode HTTP mode: "AUTO", "HTTP_1", "HTTP_2", "HTTP_2_IGNORE_ALPN".
     * @param connectionId Optional connection ID for request multiplexing.
     * @return JSON object with request/response details and timing.
     */
    fun sendRequest(
        url: String?,
        method: String?,
        headers: Map<String, String>?,
        body: String?,
        rawRequest: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        httpMode: String?,
        connectionId: String?,
        maxBodyLength: Int? = null,
        timeoutMs: Long? = null,
        preserveHeaders: Boolean = true,
        autoFixContentLength: Boolean = true
    ): JsonObject {
        return try {
            val httpRequest = buildRequest(
                url, method, headers, body, rawRequest, host, port, useTls,
                preserveHeaders = preserveHeaders,
                autoFixContentLength = autoFixContentLength
            )
            val mode = resolveHttpMode(httpMode)

            val targetUrl = try { httpRequest.url() } catch (_: Exception) { url ?: "" }
            val scope = checkScope(targetUrl)
            scope.deny?.let { return it }

            val startTime = System.nanoTime()
            val result: HttpRequestResponse = executeWithTimeout(timeoutMs) {
                if (connectionId != null) {
                    api.http().sendRequest(httpRequest, mode, connectionId)
                } else {
                    api.http().sendRequest(httpRequest, mode)
                }
            }
            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

            addToSitemap(result, "[MCP] http_send_request via BurpMCP-Ultra")
            ToolCallTracker.lastSentResult.set(result)

            withScopeWarning(serializeRequestResponse(result, elapsedMs, maxBodyLength), scope.warning)
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to send request: ${e.message}")
                put("is_timeout", (e.message ?: "").contains("timed out", ignoreCase = true))
            }
        }
    }

    /**
     * Sends multiple HTTP requests in parallel.
     *
     * @param requests List of request descriptors (each a map of URL/method/headers/body/raw_request/host/port/use_tls).
     * @param httpMode HTTP mode for all requests.
     * @return JSON object with results array.
     */
    fun sendRequestsParallel(
        requests: List<JsonObject>,
        httpMode: String?,
        maxBodyLength: Int? = null,
        timeoutMs: Long? = null
    ): JsonObject {
        return try {
            val mode = resolveHttpMode(httpMode)

            // Build all requests, recording original index and any per-request build errors.
            data class Built(val originalIndex: Int, val request: HttpRequest?, val error: String?)
            val built = requests.mapIndexed { idx, reqObj ->
                try {
                    val rawReq = reqObj["raw_request"]?.jsonPrimitive?.contentOrNull
                    val reqUrl = reqObj["url"]?.jsonPrimitive?.contentOrNull
                    val reqMethod = reqObj["method"]?.jsonPrimitive?.contentOrNull
                    val reqBody = reqObj["body"].asBodyString()
                    val reqHost = reqObj["host"]?.jsonPrimitive?.contentOrNull
                    val reqPort = reqObj["port"]?.jsonPrimitive?.intOrNull
                    val reqTls = reqObj["use_tls"]?.jsonPrimitive?.booleanOrNull
                    val reqHeaders = reqObj["headers"].asStringMap()
                    val httpReq = buildRequest(reqUrl, reqMethod, reqHeaders, reqBody, rawReq, reqHost, reqPort, reqTls)
                    Built(idx, httpReq, null)
                } catch (e: Exception) {
                    Built(idx, null, e.message ?: "Failed to build request")
                }
            }

            // Group successfully-built requests by HttpService (host+port+tls). Burp's
            // sendRequests() rejects mixed services with "HTTP service on each request must
            // be the same"; this fix groups by service and dispatches each group separately.
            val grouped = built.filter { it.request != null }.groupBy { b ->
                val svc = b.request!!.httpService()
                Triple(svc.host(), svc.port(), svc.secure())
            }

            // Storage for results in original-input order.
            val resultsArray = arrayOfNulls<HttpRequestResponse>(requests.size)
            val perGroupTimings = mutableMapOf<String, Long>()

            val totalStart = System.nanoTime()
            executeWithTimeout(timeoutMs) {
                grouped.forEach { (svc, group) ->
                    val groupKey = "${svc.first}:${svc.second}:${if (svc.third) "tls" else "plain"}"
                    val groupRequests = group.map { it.request!! }
                    val groupStart = System.nanoTime()
                    val groupResults = try {
                        api.http().sendRequests(groupRequests, mode)
                    } catch (e: Exception) {
                        // If a single group fails, leave its slots null; carry on with others.
                        emptyList()
                    }
                    perGroupTimings[groupKey] = (System.nanoTime() - groupStart) / 1_000_000
                    group.forEachIndexed { gIdx, b ->
                        if (gIdx < groupResults.size) {
                            resultsArray[b.originalIndex] = groupResults[gIdx]
                        }
                    }
                }
                Unit
            }
            val totalElapsedMs = (System.nanoTime() - totalStart) / 1_000_000

            // Add successful results to sitemap.
            resultsArray.filterNotNull().forEach { result ->
                addToSitemap(result, "[MCP] Parallel request via BurpMCP-Ultra")
            }

            buildJsonObject {
                put("total_requests", requests.size)
                put("total_responses", resultsArray.count { it != null })
                put("total_elapsed_ms", totalElapsedMs)
                put("groups_dispatched", grouped.size)
                put("group_timings_ms", buildJsonObject {
                    perGroupTimings.forEach { (k, v) -> put(k, v) }
                })
                put("results", buildJsonArray {
                    built.forEach { b ->
                        val result = resultsArray[b.originalIndex]
                        add(buildJsonObject {
                            put("index", b.originalIndex)
                            when {
                                b.error != null -> {
                                    put("error", b.error)
                                    put("phase", "build")
                                }
                                result != null -> {
                                    serializeRequestResponse(result, null, maxBodyLength).forEach { (k, v) -> put(k, v) }
                                }
                                else -> {
                                    put("error", "Send failed (group dispatch error or no response)")
                                    put("phase", "send")
                                }
                            }
                        })
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to send parallel requests: ${e.message}")
                put("is_timeout", (e.message ?: "").contains("timed out", ignoreCase = true))
            }
        }
    }

    /**
     * Executes a chain of HTTP requests sequentially, extracting variables
     * from each response and substituting them into subsequent requests.
     *
     * Each step can define:
     * - A request (url/method/headers/body/raw_request)
     * - Extract rules: list of {name, pattern (regex with capture group), from ("body" or "header")}
     *
     * Placeholders `{{variable_name}}` in subsequent steps are replaced with
     * the extracted values.
     *
     * @param steps List of step descriptors.
     * @param httpMode HTTP mode for all requests.
     * @param stopOnError Whether to stop the chain if a step fails.
     * @return JSON object with step results and extracted variables.
     */
    fun sendRequestChain(
        steps: List<JsonObject>,
        httpMode: String?,
        stopOnError: Boolean
    ): JsonObject {
        val mode = resolveHttpMode(httpMode)
        val variables = mutableMapOf<String, String>()
        val stepResults = mutableListOf<JsonObject>()

        for ((index, step) in steps.withIndex()) {
            try {
                // Substitute variables in the step's fields
                val substitutedStep = substituteVariables(step, variables)

                val rawReq = substitutedStep["raw_request"]?.jsonPrimitive?.contentOrNull
                val reqUrl = substitutedStep["url"]?.jsonPrimitive?.contentOrNull
                val reqMethod = substitutedStep["method"]?.jsonPrimitive?.contentOrNull
                val reqBody = substitutedStep["body"].asBodyString()
                val reqHost = substitutedStep["host"]?.jsonPrimitive?.contentOrNull
                val reqPort = substitutedStep["port"]?.jsonPrimitive?.intOrNull
                val reqTls = substitutedStep["use_tls"]?.jsonPrimitive?.booleanOrNull
                val reqHeaders = substitutedStep["headers"].asStringMap()

                val httpRequest = buildRequest(reqUrl, reqMethod, reqHeaders, reqBody, rawReq, reqHost, reqPort, reqTls)

                val startTime = System.nanoTime()
                val result = api.http().sendRequest(httpRequest, mode)
                val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

                addToSitemap(result, "[MCP] Chain step $index via BurpMCP-Ultra")

                // Extract variables from the response
                val extractions = substitutedStep["extract"]?.jsonArray ?: JsonArray(emptyList())
                val extractedInStep = mutableMapOf<String, String>()

                for (extractDef in extractions) {
                    val extractObj = extractDef.jsonObject
                    val varName = extractObj["name"]?.jsonPrimitive?.contentOrNull ?: continue
                    val pattern = extractObj["pattern"]?.jsonPrimitive?.contentOrNull ?: continue
                    val from = extractObj["from"]?.jsonPrimitive?.contentOrNull ?: "body"

                    val searchText = if (from.equals("header", ignoreCase = true)) {
                        result.response()?.headers()?.joinToString("\r\n") {
                            "${it.name()}: ${it.value()}"
                        } ?: ""
                    } else {
                        result.response()?.bodyToString() ?: ""
                    }

                    val regex = Regex(pattern)
                    val match = regex.find(searchText)
                    if (match != null) {
                        val extractedValue = if (match.groupValues.size > 1) {
                            match.groupValues[1]
                        } else {
                            match.value
                        }
                        variables[varName] = extractedValue
                        extractedInStep[varName] = extractedValue
                    }
                }

                val serializedResult = serializeRequestResponse(result, elapsedMs)
                stepResults.add(buildJsonObject {
                    put("step", index)
                    put("success", true)
                    serializedResult.forEach { (k, v) -> put(k, v) }
                    if (extractedInStep.isNotEmpty()) {
                        put("extracted", buildJsonObject {
                            extractedInStep.forEach { (k, v) -> put(k, v) }
                        })
                    }
                })
            } catch (e: Exception) {
                stepResults.add(buildJsonObject {
                    put("step", index)
                    put("success", false)
                    put("error", e.message ?: "Unknown error")
                })

                if (stopOnError) break
            }
        }

        return buildJsonObject {
            put("total_steps", steps.size)
            put("completed_steps", stepResults.size)
            put("variables", buildJsonObject {
                variables.forEach { (k, v) -> put(k, v) }
            })
            put("steps", buildJsonArray { stepResults.forEach { add(it) } })
        }
    }

    // ---------------------------------------------------------------
    // Cookie jar
    // ---------------------------------------------------------------

    /**
     * Returns cookies from the Burp cookie jar, optionally filtered by domain.
     *
     * @param domain Optional domain filter (case-insensitive substring match).
     * @return JSON object with cookies array.
     */
    fun getCookieJar(domain: String?): JsonObject {
        return try {
            val allCookies = api.http().cookieJar().cookies()
            val filtered = if (domain != null) {
                allCookies.filter { it.domain().contains(domain, ignoreCase = true) }
            } else {
                allCookies
            }

            buildJsonObject {
                put("total", filtered.size)
                put("cookies", buildJsonArray {
                    filtered.forEach { cookie ->
                        add(buildJsonObject {
                            put("name", cookie.name())
                            put("value", cookie.value())
                            put("domain", cookie.domain())
                            put("path", cookie.path())
                            val exp = cookie.expiration()
                            if (exp.isPresent) {
                                put("expiration", exp.get().toString())
                            }
                        })
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to get cookie jar: ${e.message}")
            }
        }
    }

    /**
     * Sets a cookie in the Burp cookie jar.
     *
     * @param name Cookie name.
     * @param value Cookie value.
     * @param domain Cookie domain.
     * @param path Cookie path.
     * @param expiration Optional expiration as ISO-8601 date-time string.
     * @return JSON object confirming the cookie was set.
     */
    fun setCookie(
        name: String,
        value: String,
        domain: String,
        path: String,
        expiration: String?
    ): JsonObject {
        return try {
            val expirationDate: ZonedDateTime? = if (expiration != null) {
                try { ZonedDateTime.parse(expiration) } catch (_: Exception) { null }
            } else {
                null
            }

            api.http().cookieJar().setCookie(name, value, domain, path, expirationDate)

            buildJsonObject {
                put("cookie_set", true)
                put("name", name)
                put("domain", domain)
                put("path", path)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to set cookie: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Response analysis
    // ---------------------------------------------------------------

    /**
     * Analyzes a response for keyword occurrences using Burp's
     * [ResponseKeywordsAnalyzer].
     *
     * @param response Raw HTTP response string.
     * @param keywords List of keywords to search for.
     * @param caseSensitive Whether keyword matching is case-sensitive.
     * @return JSON object with keyword counts.
     */
    fun analyzeKeywords(
        response: String,
        keywords: List<String>,
        caseSensitive: Boolean
    ): JsonObject {
        return try {
            // Normalize line endings: convert literal \r\n to CRLF, literal \n to LF,
            // then any bare LF to CRLF, so Montoya parses pasted responses correctly.
            val normalizedResponse = response
                .replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace(Regex("(?<!\r)\n"), "\r\n")
            val httpResponse = HttpResponse.httpResponse(normalizedResponse)
            val analyzer = api.http().createResponseKeywordsAnalyzer(keywords)
            analyzer.updateWith(httpResponse)

            buildJsonObject {
                put("variant_keywords", buildJsonArray {
                    analyzer.variantKeywords().forEach { add(it) }
                })
                put("invariant_keywords", buildJsonArray {
                    analyzer.invariantKeywords().forEach { add(it) }
                })
                put("keyword_counts", buildJsonArray {
                    httpResponse.keywordCounts(*keywords.toTypedArray()).forEach { kc ->
                        add(buildJsonObject {
                            put("keyword", kc.keyword())
                            put("count", kc.count())
                        })
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to analyze keywords: ${e.message}")
            }
        }
    }

    /**
     * Analyzes variations across multiple responses using Burp's
     * [ResponseVariationsAnalyzer].
     *
     * @param responses List of raw HTTP response strings.
     * @return JSON object with variant and invariant attributes.
     */
    fun analyzeVariations(responses: List<String>): JsonObject {
        return try {
            val analyzer: ResponseVariationsAnalyzer = api.http().createResponseVariationsAnalyzer()

            responses.forEach { rawResp ->
                // Normalize line endings so Montoya parses pasted responses correctly.
                val normalizedResp = rawResp
                    .replace("\\r\\n", "\r\n")
                    .replace("\\n", "\n")
                    .replace(Regex("(?<!\r)\n"), "\r\n")
                val httpResponse = HttpResponse.httpResponse(normalizedResp)
                analyzer.updateWith(httpResponse)
            }

            buildJsonObject {
                put("responses_analyzed", responses.size)
                put("variant_attributes", buildJsonArray {
                    analyzer.variantAttributes().forEach { attr ->
                        add(attr.name)
                    }
                })
                put("invariant_attributes", buildJsonArray {
                    analyzer.invariantAttributes().forEach { attr ->
                        add(attr.name)
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to analyze variations: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Global HTTP handler (registered during extension init)
    // ---------------------------------------------------------------

    /**
     * Creates an [HttpHandler] that applies [TrafficRule]s from the
     * [StateManager] to all outgoing requests and incoming responses.
     *
     * This handler is registered once during extension initialization in
     * [BurpMcpUltraExtension.registerBurpHandlers].
     */
    fun createGlobalHttpHandler(): HttpHandler {
        return object : HttpHandler {
            override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
                var currentRequest: HttpRequest = requestToBeSent
                var currentAnnotations = requestToBeSent.annotations()

                val matchingRules = stateManager.trafficRules.filter { rule ->
                    rule.enabled && rule.direction.equals("request", ignoreCase = true) &&
                        matchesTrafficRuleRequest(rule, requestToBeSent)
                }

                for (rule in matchingRules) {
                    currentRequest = applyTrafficRuleToRequest(rule, currentRequest)

                    eventBus.emit("http.traffic_rule.applied", buildJsonObject {
                        put("rule_id", rule.ruleId)
                        put("direction", "request")
                        put("url", requestToBeSent.url())
                        put("timestamp", Instant.now().toString())
                    })
                }

                var sessionChanged = false

                // Session-handling rules: inject previously-extracted values into the request.
                val reqUrl = requestToBeSent.url()
                for (rule in stateManager.sessionRules) {
                    if (!rule.enabled) continue
                    val value = rule.lastExtractedValue ?: continue
                    val suiteInScope = try { api.scope().isInScope(reqUrl) } catch (_: Exception) { false }
                    if (!SessionRuleEngine.inScope(rule, reqUrl, suiteInScope)) continue
                    val before = currentRequest
                    currentRequest = applySessionInjection(rule, currentRequest, value)
                    if (currentRequest !== before) {
                        sessionChanged = true
                        eventBus.emit("session.rule.injected", buildJsonObject {
                            put("rule", rule.ruleName)
                            put("url", reqUrl)
                            put("inject_into", rule.injectInto)
                            put("timestamp", Instant.now().toString())
                        })
                    }
                }

                return if (matchingRules.isEmpty() && !sessionChanged) {
                    RequestToBeSentAction.continueWith(requestToBeSent)
                } else {
                    RequestToBeSentAction.continueWith(currentRequest, currentAnnotations)
                }
            }

            override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
                var currentResponse: HttpResponse = responseReceived
                var currentAnnotations = responseReceived.annotations()

                val matchingRules = stateManager.trafficRules.filter { rule ->
                    rule.enabled && rule.direction.equals("response", ignoreCase = true) &&
                        matchesTrafficRuleResponse(rule, responseReceived)
                }

                for (rule in matchingRules) {
                    currentResponse = applyTrafficRuleToResponse(rule, currentResponse)

                    eventBus.emit("http.traffic_rule.applied", buildJsonObject {
                        put("rule_id", rule.ruleId)
                        put("direction", "response")
                        try {
                            put("url", responseReceived.initiatingRequest()?.url() ?: "")
                        } catch (_: Exception) { }
                        put("timestamp", Instant.now().toString())
                    })
                }

                // Session-handling rules: extract token/CSRF values for later injection.
                val respUrl = try { responseReceived.initiatingRequest()?.url() ?: "" } catch (_: Exception) { "" }
                for (rule in stateManager.sessionRules) {
                    if (!rule.enabled) continue
                    val suiteInScope = try { api.scope().isInScope(respUrl) } catch (_: Exception) { false }
                    if (!SessionRuleEngine.inScope(rule, respUrl, suiteInScope)) continue
                    val headerValue = if (rule.extractFrom.equals("header", true) && rule.extractHeaderName != null)
                        try { currentResponse.headerValue(rule.extractHeaderName) } catch (_: Exception) { null } else null
                    val body = try { currentResponse.bodyToString() } catch (_: Exception) { "" }
                    val extracted = SessionRuleEngine.extract(rule, headerValue, body)
                    if (extracted != null && extracted != rule.lastExtractedValue) {
                        rule.lastExtractedValue = extracted
                        eventBus.emit("session.rule.extracted", buildJsonObject {
                            put("rule", rule.ruleName)
                            put("url", respUrl)
                            put("timestamp", Instant.now().toString())
                        })
                    }
                }

                return if (matchingRules.isEmpty()) {
                    ResponseReceivedAction.continueWith(responseReceived)
                } else {
                    ResponseReceivedAction.continueWith(currentResponse, currentAnnotations)
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Session-handling rule application
    // ---------------------------------------------------------------

    /**
     * Injects a rendered session value into [request] per the rule's
     * `injectInto` target. Header injection is CRLF-validated; cookie/body use
     * upsert semantics so repeated requests don't accumulate duplicates.
     */
    private fun applySessionInjection(rule: SessionRule, request: HttpRequest, value: String): HttpRequest {
        val rendered = SessionRuleEngine.render(rule.injectValueTemplate, value)
        return when (rule.injectInto.lowercase()) {
            "header" ->
                if (HeaderSafety.isValidHeaderName(rule.injectName) && HeaderSafety.isValidHeaderValue(rendered))
                    request.withUpdatedHeader(rule.injectName, rendered)
                else request
            "cookie" -> upsertParam(request, HttpParameter.cookieParameter(rule.injectName, rendered))
            "body" -> upsertParam(request, HttpParameter.bodyParameter(rule.injectName, rendered))
            else -> request
        }
    }

    private fun upsertParam(request: HttpRequest, param: HttpParameter): HttpRequest =
        if (request.hasParameter(param.name(), param.type())) request.withUpdatedParameters(param)
        else request.withAddedParameters(param)

    // ---------------------------------------------------------------
    // Traffic rule matching helpers
    // ---------------------------------------------------------------

    private fun matchesTrafficRuleRequest(rule: TrafficRule, request: HttpRequestToBeSent): Boolean {
        if (rule.matchUrl != null) {
            if (!SafeRegex.containsMatchIn(rule.matchUrl, request.url(), ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchHost != null) {
            val hostPattern = rule.matchHost.replace("*", ".*")
            if (!SafeRegex.matches(hostPattern, request.httpService().host(), ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchHeader != null) {
            val headerStr = request.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
            if (!SafeRegex.containsMatchIn(rule.matchHeader, headerStr, ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    private fun matchesTrafficRuleResponse(rule: TrafficRule, response: HttpResponseReceived): Boolean {
        if (rule.matchUrl != null) {
            val url = try { response.initiatingRequest()?.url() } catch (_: Exception) { null }
            if (url != null && !SafeRegex.containsMatchIn(rule.matchUrl, url, ignoreCase = true)) {
                return false
            }
        }
        if (rule.matchHost != null) {
            val host = try { response.initiatingRequest()?.httpService()?.host() } catch (_: Exception) { null }
            if (host != null) {
                val hostPattern = rule.matchHost.replace("*", ".*")
                if (!SafeRegex.matches(hostPattern, host, ignoreCase = true)) {
                    return false
                }
            }
        }
        if (rule.matchHeader != null) {
            val headerStr = response.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
            if (!SafeRegex.containsMatchIn(rule.matchHeader, headerStr, ignoreCase = true)) {
                return false
            }
        }
        return true
    }

    // ---------------------------------------------------------------
    // Traffic rule application helpers
    // ---------------------------------------------------------------

    private fun applyTrafficRuleToRequest(rule: TrafficRule, request: HttpRequest): HttpRequest {
        var modified = request

        if (rule.modifyAddHeader != null) {
            HeaderSafety.parseHeaderLine(rule.modifyAddHeader)?.let { (name, value) ->
                modified = modified.withAddedHeader(name, value)
            }
        }
        if (rule.modifyRemoveHeader != null) {
            modified = modified.withRemovedHeader(rule.modifyRemoveHeader)
        }
        rule.modifyReplaceHeader?.forEach { (headerName, headerValue) ->
            modified = modified.withUpdatedHeader(headerName, headerValue)
        }

        return modified
    }

    private fun applyTrafficRuleToResponse(rule: TrafficRule, response: HttpResponse): HttpResponse {
        var modified = response

        if (rule.modifyAddHeader != null) {
            HeaderSafety.parseHeaderLine(rule.modifyAddHeader)?.let { (name, value) ->
                modified = modified.withAddedHeader(name, value)
            }
        }
        if (rule.modifyRemoveHeader != null) {
            modified = modified.withRemovedHeader(rule.modifyRemoveHeader)
        }
        rule.modifyReplaceHeader?.forEach { (headerName, headerValue) ->
            modified = modified.withUpdatedHeader(headerName, headerValue)
        }

        return modified
    }

    // ---------------------------------------------------------------
    // Request building helpers
    // ---------------------------------------------------------------

    /**
     * Builds an [HttpRequest] from either a raw string or structured parameters.
     *
     * Behaviour notes (fixes for known agent-reported issues):
     * - When [rawRequest] lacks port info, defaults to TLS:443 (modern web default)
     *   instead of plain:80. Honour explicit [port]/[useTls] overrides.
     * - When [url] + [headers] are both supplied AND [preserveHeaders] is true (default),
     *   constructs a complete raw HTTP request preserving the caller's headers byte-exact,
     *   bypassing Burp's default User-Agent/Accept/etc. injection.
     * - Auto-recomputes Content-Length on raw_request if it is wrong (silent CL bugs
     *   are responsible for ghost status_code:0 responses).
     */
    private fun buildRequest(
        url: String?,
        method: String?,
        headers: Map<String, String>?,
        body: String?,
        rawRequest: String?,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        preserveHeaders: Boolean = true,
        autoFixContentLength: Boolean = true
    ): HttpRequest {
        var request: HttpRequest = if (rawRequest != null) {
            buildFromRawRequest(rawRequest, host, port, useTls, autoFixContentLength)
        } else if (url != null) {
            if (preserveHeaders && !headers.isNullOrEmpty()) {
                buildFromUrlPreservingHeaders(url, method, headers, body, host, port, useTls)
            } else {
                buildFromUrlMontoya(url, method, headers, body, host, port, useTls)
            }
        } else {
            throw IllegalArgumentException("Either 'url' or 'raw_request' must be provided")
        }

        // For raw_request: allow extra header overrides via headers map (replaces existing)
        if (rawRequest != null) {
            headers?.forEach { (name, value) ->
                request = request.withHeader(name, value)
            }
        }

        return request
    }

    /**
     * Builds a request from raw HTTP text, defaulting to TLS:443 when port info is absent.
     * Auto-fixes Content-Length on the raw request if [autoFixContentLength] is true.
     */
    private fun buildFromRawRequest(
        rawRequest: String,
        host: String?,
        port: Int?,
        useTls: Boolean?,
        autoFixContentLength: Boolean
    ): HttpRequest {
        val cleaned = if (autoFixContentLength) fixContentLength(rawRequest) else rawRequest

        val resolvedHost = host ?: Regex("(?i)^Host:\\s*([^:\\r\\n]+)", RegexOption.MULTILINE)
            .find(cleaned)?.groupValues?.get(1)?.trim()

        if (resolvedHost == null) {
            return HttpRequest.httpRequest(cleaned)
        }

        val hostHeaderPort = if (host == null) {
            Regex("(?i)^Host:\\s*[^:]+:(\\d+)", RegexOption.MULTILINE)
                .find(cleaned)?.groupValues?.get(1)?.toIntOrNull()
        } else null

        // Modern web default: TLS:443 unless caller explicitly says otherwise
        val effectivePort = port ?: hostHeaderPort ?: 443
        val effectiveTls = useTls ?: (effectivePort != 80)

        val service = HttpService.httpService(resolvedHost, effectivePort, effectiveTls)
        return HttpRequest.httpRequest(service, cleaned)
    }

    /**
     * Builds a request from URL + headers as a complete raw HTTP request, preserving the
     * caller's headers exactly. Bypasses Burp's default header injection (User-Agent,
     * Accept, Accept-Language, etc.) which silently overrides caller-supplied values.
     */
    private fun buildFromUrlPreservingHeaders(
        url: String,
        method: String?,
        headers: Map<String, String>,
        body: String?,
        hostOverride: String?,
        portOverride: Int?,
        tlsOverride: Boolean?
    ): HttpRequest {
        val (svcHost, svcPort, svcTls) = resolveService(url, hostOverride, portOverride, tlsOverride)
        val rawHttp = constructRawHttpRequest(url, method ?: "GET", headers, body, svcHost, svcPort, svcTls)
        val service = HttpService.httpService(svcHost, svcPort, svcTls)
        return HttpRequest.httpRequest(service, rawHttp)
    }

    /**
     * Legacy/Burp-managed path: uses Montoya's [HttpRequest.httpRequestFromUrl] which adds
     * Burp's default headers, then layers user headers on top via withHeader (replaces if
     * present). Use this when [preserveHeaders] is false.
     */
    private fun buildFromUrlMontoya(
        url: String,
        method: String?,
        headers: Map<String, String>?,
        body: String?,
        hostOverride: String?,
        portOverride: Int?,
        tlsOverride: Boolean?
    ): HttpRequest {
        var req = HttpRequest.httpRequestFromUrl(url)
        if (method != null) req = req.withMethod(method)
        if (body != null) req = req.withBody(body)
        headers?.forEach { (n, v) -> req = req.withHeader(n, v) }
        if (hostOverride != null) {
            val tls = tlsOverride ?: url.startsWith("https", ignoreCase = true)
            val effectivePort = portOverride ?: if (tls) 443 else 80
            req = req.withService(HttpService.httpService(hostOverride, effectivePort, tls))
        }
        return req
    }

    /**
     * Resolves (host, port, tls) from a URL + optional overrides.
     */
    private fun resolveService(
        url: String,
        hostOverride: String?,
        portOverride: Int?,
        tlsOverride: Boolean?
    ): Triple<String, Int, Boolean> {
        val uri = try { URI(url) } catch (_: Exception) { null }
        val tls = tlsOverride ?: (uri?.scheme?.equals("https", ignoreCase = true) ?: url.startsWith("https"))
        val host = hostOverride ?: uri?.host ?: throw IllegalArgumentException("Cannot extract host from URL: $url")
        val port = portOverride ?: when {
            uri != null && uri.port > 0 -> uri.port
            tls -> 443
            else -> 80
        }
        return Triple(host, port, tls)
    }

    /**
     * Constructs a complete raw HTTP/1.1 request from structured parameters.
     * Exactly preserves caller headers; auto-adds Host and Content-Length only if missing.
     */
    private fun constructRawHttpRequest(
        url: String,
        method: String,
        headers: Map<String, String>,
        body: String?,
        host: String,
        port: Int,
        tls: Boolean
    ): String {
        val uri = try { URI(url) } catch (_: Exception) { null }
        val pathPart = uri?.rawPath?.ifEmpty { "/" } ?: "/"
        val queryPart = uri?.rawQuery?.let { "?$it" } ?: ""
        val requestTarget = "$pathPart$queryPart"

        val isDefaultPort = (tls && port == 443) || (!tls && port == 80)
        val hostHeader = if (isDefaultPort) host else "$host:$port"

        val sb = StringBuilder()
        sb.append("$method $requestTarget HTTP/1.1\r\n")

        val hasHost = headers.keys.any { it.equals("Host", ignoreCase = true) }
        if (!hasHost) sb.append("Host: $hostHeader\r\n")

        headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }

        val hasContentLength = headers.keys.any { it.equals("Content-Length", ignoreCase = true) }
        val hasTransferEncoding = headers.keys.any { it.equals("Transfer-Encoding", ignoreCase = true) }
        if (body != null && !hasContentLength && !hasTransferEncoding) {
            val bodyBytes = body.toByteArray(Charsets.ISO_8859_1)
            sb.append("Content-Length: ${bodyBytes.size}\r\n")
        }

        sb.append("\r\n")
        if (body != null) sb.append(body)

        return sb.toString()
    }

    /**
     * Recomputes the Content-Length header on a raw HTTP request to match the actual
     * body size in bytes (ISO-8859-1). Returns the original request unchanged if there
     * is no body section or no Content-Length header.
     *
     * Fixes the silent status_code:0 ghost response when caller-computed CL is wrong.
     */
    private fun fixContentLength(rawRequest: String): String {
        val boundary = rawRequest.indexOf("\r\n\r\n")
        if (boundary < 0) return rawRequest

        val headerSection = rawRequest.substring(0, boundary)
        val bodySection = rawRequest.substring(boundary + 4)

        val clRegex = Regex("(?im)^Content-Length:\\s*(\\d+)\\s*$")
        val clMatch = clRegex.find(headerSection) ?: return rawRequest

        val declaredLength = clMatch.groupValues[1].toIntOrNull() ?: return rawRequest
        val actualLength = bodySection.toByteArray(Charsets.ISO_8859_1).size
        if (declaredLength == actualLength) return rawRequest

        val fixedHeader = clRegex.replaceFirst(headerSection, "Content-Length: $actualLength")
        return "$fixedHeader\r\n\r\n$bodySection"
    }

    // ---------------------------------------------------------------
    // Timeout-bounded execution
    // ---------------------------------------------------------------

    private val httpExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "burpmcp-http-${System.nanoTime()}").apply { isDaemon = true }
    }

    /**
     * Runs [action] on a daemon thread with a hard timeout. On timeout, cancels the
     * future (Burp request continues in background but caller is unblocked) and throws.
     * If [timeoutMs] is null or non-positive, runs synchronously without overhead.
     */
    private fun <T> executeWithTimeout(timeoutMs: Long?, action: () -> T): T {
        if (timeoutMs == null || timeoutMs <= 0) return action()
        val future = httpExecutor.submit(Callable { action() })
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            future.cancel(true)
            throw RuntimeException("Request timed out after ${timeoutMs}ms")
        }
    }

    // ---------------------------------------------------------------
    // Raw bytes request (byte-level control for smuggling)
    // ---------------------------------------------------------------

    /**
     * Sends a raw byte-level HTTP request for HTTP request smuggling testing.
     * Preserves exact byte sequences including CRLF injection characters.
     *
     * @param rawHex Hex-encoded raw bytes (e.g. "474554202f...").
     * @param rawString String with literal \r\n sequences converted to actual CRLF.
     * @param host Target host.
     * @param port Target port.
     * @param useTls Whether to use TLS.
     * @param httpMode HTTP mode string.
     * @param maxBodyLength Optional response body truncation length.
     * @return JSON object with serialized request/response.
     */
    fun sendRawBytes(
        rawHex: String?,
        rawString: String?,
        host: String,
        port: Int,
        useTls: Boolean,
        httpMode: String?,
        maxBodyLength: Int? = null,
        timeoutMs: Long? = null
    ): JsonObject {
        return try {
            val bytes = if (rawHex != null) {
                rawHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            } else if (rawString != null) {
                rawString.replace("\\r\\n", "\r\n").replace("\\n", "\n").toByteArray(Charsets.ISO_8859_1)
            } else {
                throw IllegalArgumentException("Either raw_request_hex or raw_request must be provided")
            }

            val service = HttpService.httpService(host, port, useTls)
            val httpRequest = HttpRequest.httpRequest(service, BurpByteArray.byteArray(*bytes))
            val mode = resolveHttpMode(httpMode)

            val targetUrl = try { httpRequest.url() } catch (_: Exception) { (if (useTls) "https" else "http") + "://$host:$port/" }
            val scope = checkScope(targetUrl)
            scope.deny?.let { return it }

            val startTime = System.nanoTime()
            val result = executeWithTimeout(timeoutMs) { api.http().sendRequest(httpRequest, mode) }
            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

            addToSitemap(result, "[MCP] Raw bytes request via BurpMCP-Ultra")
            ToolCallTracker.lastSentResult.set(result)

            withScopeWarning(serializeRequestResponse(result, elapsedMs, maxBodyLength), scope.warning)
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to send raw bytes: ${e.message}")
                put("is_timeout", (e.message ?: "").contains("timed out", ignoreCase = true))
            }
        }
    }

    // ---------------------------------------------------------------
    // Scope policy gate (operator-controlled; the agent cannot change it)
    // ---------------------------------------------------------------

    /** Reads the operator-set enforcement mode from Burp preferences (key `mcp_scope_mode`). */
    private fun scopeMode(): ScopeMode =
        ScopeMode.fromString(
            try { api.persistence().preferences().getString("mcp_scope_mode") } catch (_: Exception) { null }
        )

    /** Result of a scope check: [deny] (return it to block the send) and/or a [warning] to attach. */
    private data class ScopeCheck(val deny: JsonObject?, val warning: String?)

    /**
     * Evaluates an outbound [url] against Burp's target scope under the operator
     * policy. Fails open (allows) when scope cannot be evaluated, so a Burp
     * quirk never blocks legitimate work.
     */
    private fun checkScope(url: String): ScopeCheck {
        val mode = scopeMode()
        if (mode == ScopeMode.OFF) return ScopeCheck(null, null)
        val inScope = try { api.scope().isInScope(url) } catch (_: Exception) { return ScopeCheck(null, null) }
        return when (ScopePolicy.decide(mode, inScope)) {
            ScopeDecision.DENY -> ScopeCheck(
                buildJsonObject {
                    put(
                        "error",
                        "Blocked by scope policy: target is not in Burp's scope. An operator can allow it by " +
                            "adding it to Burp's target scope or setting preference mcp_scope_mode to 'warn' or 'off'."
                    )
                    put("out_of_scope", true)
                    put("url", url)
                    put("scope_mode", "enforce")
                },
                null
            )
            ScopeDecision.WARN -> ScopeCheck(null, "out_of_scope: target is not in Burp's target scope")
            ScopeDecision.ALLOW -> ScopeCheck(null, null)
        }
    }

    /** Returns [base] with a `scope_warning` field appended when [warning] is non-null. */
    private fun withScopeWarning(base: JsonObject, warning: String?): JsonObject =
        if (warning == null) base else JsonObject(base + ("scope_warning" to JsonPrimitive(warning)))

    // ---------------------------------------------------------------
    // Fuzzer (intruder-like payload injection)
    // ---------------------------------------------------------------

    /**
     * Sends requests with payloads injected at marked positions (sniper mode).
     * For each payload, each position is substituted one at a time.
     *
     * @param request The base request string (ISO-8859-1).
     * @param host Target host.
     * @param port Target port.
     * @param useTls Whether to use TLS.
     * @param positions List of [start, end] offset pairs marking injection points.
     * @param payloads List of payload strings to inject.
     * @param httpMode HTTP mode string.
     * @param maxBodyLength Optional response body truncation length.
     * @return JSON object with all fuzz results.
     */
    /**
     * Fuzz using markers: the request contains `§` markers (or a custom marker string)
     * around injection points, like Burp Intruder. Each marker pair is replaced with
     * each payload. Example: `GET /api?id=§1§ HTTP/1.1` with payloads `["1","2","3"]`.
     *
     * Also supports a simple `FUZZ` keyword mode: if the request contains the literal
     * string `FUZZ`, each occurrence is replaced with each payload. No marker pairs needed.
     *
     * Legacy offset-based mode is still supported via the `positions` parameter.
     */
    fun fuzz(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        positions: List<Pair<Int, Int>>?,
        payloads: List<String>,
        httpMode: String?,
        maxBodyLength: Int?,
        marker: String?
    ): JsonObject {
        return try {
            val service = HttpService.httpService(host, port, useTls)
            val mode = resolveHttpMode(httpMode)
            val results = mutableListOf<JsonObject>()

            // Normalize the request string: convert literal \r\n to CRLF, bare \n to CRLF
            val baseRequest = request
                .replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace(Regex("(?<!\r)\n"), "\r\n")

            // Determine injection mode
            val effectiveMarker = marker ?: "§"
            val hasFuzzKeyword = baseRequest.contains("FUZZ")
            val hasMarkerPairs = baseRequest.contains(effectiveMarker) &&
                baseRequest.count { it == effectiveMarker[0] } >= 2

            when {
                // Mode 1: FUZZ keyword — replace every occurrence of "FUZZ" with each payload
                hasFuzzKeyword && !hasMarkerPairs -> {
                    for (payload in payloads) {
                        val modified = baseRequest.replace("FUZZ", payload)
                        val httpRequest = HttpRequest.httpRequest(service, modified)
                        val startTime = System.nanoTime()
                        val result = api.http().sendRequest(httpRequest, mode)
                        val elapsedMs = (System.nanoTime() - startTime) / 1_000_000
                        addToSitemap(result, "[MCP] Fuzz payload=$payload via BurpMCP-Ultra")

                        results.add(buildJsonObject {
                            put("payload", payload)
                            put("position", 0)
                            serializeRequestResponse(result, elapsedMs, maxBodyLength).forEach { (k, v) -> put(k, v) }
                        })
                    }
                }

                // Mode 2: Marker pairs — find §value§ pairs, replace each with payloads (sniper mode)
                hasMarkerPairs -> {
                    // Find all marker-delimited positions
                    val markerPositions = mutableListOf<Pair<Int, Int>>()
                    var searchFrom = 0
                    while (true) {
                        val openIdx = baseRequest.indexOf(effectiveMarker, searchFrom)
                        if (openIdx < 0) break
                        val closeIdx = baseRequest.indexOf(effectiveMarker, openIdx + effectiveMarker.length)
                        if (closeIdx < 0) break
                        markerPositions.add(Pair(openIdx, closeIdx + effectiveMarker.length))
                        searchFrom = closeIdx + effectiveMarker.length
                    }

                    for (payload in payloads) {
                        for ((posIdx, pos) in markerPositions.withIndex()) {
                            val (start, end) = pos
                            val modified = baseRequest.substring(0, start) + payload + baseRequest.substring(end)
                            val httpRequest = HttpRequest.httpRequest(service, modified)
                            val startTime = System.nanoTime()
                            val result = api.http().sendRequest(httpRequest, mode)
                            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000
                            addToSitemap(result, "[MCP] Fuzz marker pos=$posIdx payload=$payload")

                            results.add(buildJsonObject {
                                put("payload", payload)
                                put("position", posIdx)
                                serializeRequestResponse(result, elapsedMs, maxBodyLength).forEach { (k, v) -> put(k, v) }
                            })
                        }
                    }
                }

                // Mode 3: Legacy offset-based positions
                positions != null && positions.isNotEmpty() -> {
                    for (payload in payloads) {
                        for ((posIdx, pos) in positions.withIndex()) {
                            val (start, end) = pos
                            val modified = baseRequest.substring(0, start) + payload + baseRequest.substring(end)
                            val httpRequest = HttpRequest.httpRequest(service, modified)
                            val startTime = System.nanoTime()
                            val result = api.http().sendRequest(httpRequest, mode)
                            val elapsedMs = (System.nanoTime() - startTime) / 1_000_000
                            addToSitemap(result, "[MCP] Fuzz offset pos=$posIdx payload=$payload")

                            results.add(buildJsonObject {
                                put("payload", payload)
                                put("position", posIdx)
                                serializeRequestResponse(result, elapsedMs, maxBodyLength).forEach { (k, v) -> put(k, v) }
                            })
                        }
                    }
                }

                else -> {
                    return buildJsonObject {
                        put("error", "No injection points found. Use FUZZ keyword, §marker§ pairs, or positions array.")
                    }
                }
            }

            buildJsonObject {
                put("total_requests", results.size)
                put("payloads_count", payloads.size)
                put("mode", when {
                    hasFuzzKeyword && !hasMarkerPairs -> "fuzz_keyword"
                    hasMarkerPairs -> "marker_pairs"
                    else -> "offset"
                })
                put("results", buildJsonArray { results.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Fuzz failed: ${e.message}")
            }
        }
    }

    // ---------------------------------------------------------------
    // Race condition tester
    // ---------------------------------------------------------------

    /**
     * Race condition tester: dispatches N requests concurrently via Burp's parallel
     * request engine ([burp.api.montoya.http.Http.sendRequests]) and analyzes the
     * responses for variations (status codes, body lengths) that indicate the server
     * handles concurrent requests inconsistently.
     *
     * NOTE: This is best-effort concurrency, NOT guaranteed single-packet / last-byte
     * synchronization. Requests are built up front and handed to Burp's parallel sender
     * in one batch; Burp dispatches them as concurrently as the engine and transport
     * allow. There is no microsecond-level last-byte gate — use this to surface likely
     * race conditions, not to guarantee a precise arrival window.
     *
     * @param request Base HTTP request string (use FUZZ for varied payloads)
     * @param host Target host
     * @param port Target port
     * @param useTls Use TLS
     * @param count Number of concurrent requests (default 10). IGNORED when [payloads]
     *   is non-empty — in that case one request is built per payload and [payloads]
     *   takes precedence.
     * @param payloads Optional: if provided, each request gets a different payload
     *   replacing the FUZZ keyword, and the request count equals payloads.size.
     * @param httpMode HTTP mode
     * @param maxBodyLength Response truncation
     * @param gateDelay Milliseconds to sleep immediately before dispatching the batch
     *   (a simple pre-dispatch gate). 0 or negative dispatches immediately (default 100).
     */
    fun raceCondition(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        count: Int,
        payloads: List<String>?,
        httpMode: String?,
        maxBodyLength: Int?,
        gateDelay: Long
    ): JsonObject {
        return try {
            val service = HttpService.httpService(host, port, useTls)
            val mode = resolveHttpMode(httpMode)

            // Normalize request
            val baseRequest = request
                .replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace(Regex("(?<!\r)\n"), "\r\n")

            // Build all requests
            val requests = if (payloads != null && payloads.isNotEmpty()) {
                payloads.map { payload ->
                    HttpRequest.httpRequest(service, baseRequest.replace("FUZZ", payload))
                }
            } else {
                (1..count).map { HttpRequest.httpRequest(service, baseRequest) }
            }

            // Optional pre-dispatch gate: sleep gateDelay ms before releasing the batch.
            if (gateDelay > 0) {
                try { Thread.sleep(gateDelay) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            }

            // Send all requests in parallel using Burp's parallel sender (best-effort
            // concurrency — see kdoc; this is NOT guaranteed single-packet sync).
            val startTime = System.nanoTime()
            val responses = api.http().sendRequests(requests, mode)
            val totalElapsedMs = (System.nanoTime() - startTime) / 1_000_000

            // Analyze results for race condition indicators
            val statusCodes = mutableMapOf<Int, Int>()
            val bodyLengths = mutableMapOf<Int, Int>()
            val resultsList = mutableListOf<JsonObject>()

            responses.forEachIndexed { index, result ->
                addToSitemap(result, "[MCP] Race request #$index via BurpMCP-Ultra")
                val statusCode = try { result.response()?.statusCode()?.toInt() ?: 0 } catch (_: Throwable) { 0 }
                val bodyLen = try { result.response()?.body()?.length() ?: 0 } catch (_: Throwable) { 0 }

                statusCodes[statusCode] = (statusCodes[statusCode] ?: 0) + 1
                bodyLengths[bodyLen] = (bodyLengths[bodyLen] ?: 0) + 1

                val serialized = serializeRequestResponse(result, null, maxBodyLength)
                resultsList.add(buildJsonObject {
                    put("index", index)
                    if (payloads != null && index < payloads.size) put("payload", payloads[index])
                    serialized.forEach { (k, v) -> put(k, v) }
                })
            }

            // Race condition analysis
            val hasStatusVariation = statusCodes.size > 1
            val hasLengthVariation = bodyLengths.size > 1
            val raceDetected = hasStatusVariation || hasLengthVariation

            buildJsonObject {
                put("total_requests", requests.size)
                put("total_elapsed_ms", totalElapsedMs)
                put("avg_ms_per_request", if (requests.isNotEmpty()) totalElapsedMs / requests.size else 0)

                put("analysis", buildJsonObject {
                    put("race_condition_likely", raceDetected)
                    put("status_code_distribution", buildJsonObject {
                        statusCodes.forEach { (code, count) -> put(code.toString(), count) }
                    })
                    put("body_length_distribution", buildJsonObject {
                        bodyLengths.forEach { (len, count) -> put(len.toString(), count) }
                    })
                    put("status_variation", hasStatusVariation)
                    put("length_variation", hasLengthVariation)
                    if (raceDetected) {
                        put("note", "Response variations detected — possible race condition. Different status codes or body lengths across identical simultaneous requests suggest the server handles concurrent requests inconsistently.")
                    }
                })

                put("results", buildJsonArray { resultsList.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Race condition test failed: ${e.message}")
            }
        }
    }

    /**
     * Resolves an HTTP mode string to an [HttpMode] enum value.
     */
    private fun resolveHttpMode(mode: String?): HttpMode {
        return when (mode?.uppercase()) {
            "HTTP_1" -> HttpMode.HTTP_1
            "HTTP_2" -> HttpMode.HTTP_2
            "HTTP_2_IGNORE_ALPN" -> HttpMode.HTTP_2_IGNORE_ALPN
            else -> HttpMode.AUTO
        }
    }

    // ---------------------------------------------------------------
    // Variable substitution for request chains
    // ---------------------------------------------------------------

    /**
     * Recursively substitutes `{{variable}}` placeholders in all string values
     * within a JSON object.
     */
    private fun substituteVariables(obj: JsonObject, variables: Map<String, String>): JsonObject {
        return buildJsonObject {
            obj.forEach { (key, value) ->
                put(key, substituteInElement(value, variables))
            }
        }
    }

    private fun substituteInElement(element: JsonElement, variables: Map<String, String>): JsonElement {
        return when (element) {
            is JsonPrimitive -> {
                if (element.isString) {
                    var result = element.content
                    variables.forEach { (varName, varValue) ->
                        result = result.replace("{{$varName}}", varValue)
                    }
                    JsonPrimitive(result)
                } else {
                    element
                }
            }
            is JsonObject -> buildJsonObject {
                element.forEach { (key, value) ->
                    put(key, substituteInElement(value, variables))
                }
            }
            is JsonArray -> buildJsonArray {
                element.forEach { add(substituteInElement(it, variables)) }
            }
        }
    }

    // ---------------------------------------------------------------
    // Response serialization
    // ---------------------------------------------------------------

    /**
     * Serializes an [HttpRequestResponse] to a [JsonObject].
     *
     * @param result The request/response pair to serialize.
     * @param elapsedMs Optional elapsed time in milliseconds.
     * @param maxBodyLength Optional maximum response body length. When null or 0, the full body is returned.
     *                      When positive, the body is truncated to this many characters.
     */
    fun serializeRequestResponse(result: HttpRequestResponse, elapsedMs: Long?, maxBodyLength: Int? = null): JsonObject {
        return buildJsonObject {
            put("has_response", result.hasResponse())
            put("url", result.url() ?: "")

            // Request info
            try {
                val req = result.request()
                if (req != null) {
                    put("request_method", req.method())
                    put("request_url", req.url())
                    put("request_host", req.httpService().host())
                    put("request_port", req.httpService().port())
                    put("request_secure", req.httpService().secure())
                    put("request_headers", buildJsonArray {
                        req.headers().forEach { h ->
                            add(buildJsonObject {
                                put("name", h.name())
                                put("value", h.value())
                            })
                        }
                    })
                    put("request_body", req.bodyToString())
                }
            } catch (_: Exception) { }

            // Response info
            if (result.hasResponse()) {
                try {
                    val resp = result.response()
                    put("status_code", resp.statusCode().toInt())
                    put("response_http_version", resp.httpVersion())
                    put("response_reason", resp.reasonPhrase() ?: "")
                    put("response_mime_type", resp.mimeType().name)
                    put("response_body_length", resp.body().length())
                    put("response_headers", buildJsonArray {
                        resp.headers().forEach { h ->
                            add(buildJsonObject {
                                put("name", h.name())
                                put("value", h.value())
                            })
                        }
                    })
                    val bodyStr = resp.bodyToString()
                    val responseBody = if (maxBodyLength != null && maxBodyLength > 0 && bodyStr.length > maxBodyLength) {
                        bodyStr.take(maxBodyLength) + "... [truncated, full length: ${bodyStr.length}]"
                    } else {
                        bodyStr
                    }
                    put("response_body", responseBody)

                    // Cookies
                    val cookies = resp.cookies()
                    if (cookies.isNotEmpty()) {
                        put("response_cookies", buildJsonArray {
                            cookies.forEach { c ->
                                add(buildJsonObject {
                                    put("name", c.name())
                                    put("value", c.value())
                                    put("domain", c.domain())
                                    put("path", c.path())
                                })
                            }
                        })
                    }
                } catch (_: Exception) { }
            }

            // Timing
            if (elapsedMs != null) {
                put("elapsed_ms", elapsedMs)
            }

            try {
                val timingOpt = result.timingData()
                if (timingOpt.isPresent) {
                    val td = timingOpt.get()
                    put("timing", buildJsonObject {
                        put("time_to_first_byte_ms", td.timeBetweenRequestSentAndStartOfResponse().toMillis())
                        put("time_to_complete_ms", td.timeBetweenRequestSentAndEndOfResponse().toMillis())
                        put("time_request_sent", td.timeRequestSent().toString())
                    })
                }
            } catch (_: Exception) { }
        }
    }
}
