package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.sitemap.SiteMapFilter
import kotlinx.serialization.json.*

/**
 * Cross-cutting analysis bridge that combines multiple Montoya APIs
 * to perform request/response analysis, reflection detection,
 * parameter extraction, diff comparison, and response body searching.
 */
class AnalysisBridge(private val api: MontoyaApi) {

    /**
     * Parses a raw HTTP request and extracts its components: method, URL,
     * path, headers, cookies, parameters, body, and content type.
     */
    fun analyzeRequest(rawRequest: String): JsonObject {
        val httpRequest = HttpRequest.httpRequest(rawRequest)

        val headers = buildJsonArray {
            for (header in httpRequest.headers()) {
                addJsonObject {
                    put("name", header.name())
                    put("value", header.value())
                }
            }
        }

        val parameters = buildJsonArray {
            for (param in httpRequest.parameters()) {
                addJsonObject {
                    put("name", param.name())
                    put("value", param.value())
                    put("type", param.type().name)
                }
            }
        }

        val cookies = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("COOKIE", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        return buildJsonObject {
            put("method", httpRequest.method())
            put("url", httpRequest.url())
            put("path", httpRequest.path())
            put("content_type", httpRequest.contentType()?.name ?: "NONE")
            put("header_count", httpRequest.headers().size)
            put("headers", headers)
            put("parameter_count", httpRequest.parameters().size)
            put("parameters", parameters)
            put("cookies", cookies)
            put("has_body", httpRequest.body() != null && httpRequest.body().length() > 0)
            put("body_length", httpRequest.body()?.length() ?: 0)
            put("body", httpRequest.bodyToString())
        }
    }

    /**
     * Parses a raw HTTP response and extracts its components: status code,
     * reason phrase, headers, cookies, body, and MIME types.
     */
    fun analyzeResponse(rawResponse: String): JsonObject {
        val httpResponse = HttpResponse.httpResponse(rawResponse)

        val headers = buildJsonArray {
            for (header in httpResponse.headers()) {
                addJsonObject {
                    put("name", header.name())
                    put("value", header.value())
                }
            }
        }

        val cookies = buildJsonArray {
            for (cookie in httpResponse.cookies()) {
                addJsonObject {
                    put("name", cookie.name())
                    put("value", cookie.value())
                    put("domain", cookie.domain() ?: "")
                    put("path", cookie.path() ?: "")
                    put("expiration", cookie.expiration()?.toString() ?: "")
                }
            }
        }

        return buildJsonObject {
            put("status_code", httpResponse.statusCode())
            put("reason_phrase", httpResponse.reasonPhrase() ?: "")
            put("stated_mime_type", httpResponse.statedMimeType()?.toString() ?: "unknown")
            put("inferred_mime_type", httpResponse.inferredMimeType()?.toString() ?: "unknown")
            put("header_count", httpResponse.headers().size)
            put("headers", headers)
            put("cookie_count", httpResponse.cookies().size)
            put("cookies", cookies)
            put("has_body", httpResponse.body() != null && httpResponse.body().length() > 0)
            put("body_length", httpResponse.body()?.length() ?: 0)
            put("body", httpResponse.bodyToString())
        }
    }

    /**
     * Finds reflected values by extracting parameter values from a request
     * and searching for them in the response body. For each reflection,
     * determines the surrounding context (HTML body, attribute, JavaScript,
     * URL, comment).
     *
     * @param rawRequest The raw HTTP request string.
     * @param rawResponse The raw HTTP response string.
     * @param additionalValues Extra values to search for beyond request params.
     */
    fun findReflected(
        rawRequest: String,
        rawResponse: String,
        additionalValues: List<String>
    ): JsonObject {
        val httpRequest = HttpRequest.httpRequest(rawRequest)
        val httpResponse = HttpResponse.httpResponse(rawResponse)
        val responseBody = httpResponse.bodyToString()

        // Collect all candidate values from request parameters
        val candidateValues = mutableMapOf<String, String>()
        for (param in httpRequest.parameters()) {
            val value = param.value()
            if (value.length >= 3) {
                candidateValues["${param.type().name}:${param.name()}"] = value
            }
        }
        // Add user-supplied additional values
        additionalValues.forEachIndexed { idx, v ->
            if (v.length >= 3) {
                candidateValues["additional:$idx"] = v
            }
        }

        val reflections = buildJsonArray {
            for ((source, value) in candidateValues) {
                if (responseBody.contains(value)) {
                    // Find all occurrences and their contexts
                    var searchFrom = 0
                    var occurrenceIndex = 0
                    while (true) {
                        val pos = responseBody.indexOf(value, searchFrom)
                        if (pos == -1) break

                        val context = determineReflectionContext(responseBody, pos, value.length)
                        addJsonObject {
                            put("source", source)
                            put("value", value)
                            put("position", pos)
                            put("occurrence", occurrenceIndex)
                            put("context", context)
                            // Show surrounding chars for analysis
                            val snippetStart = maxOf(0, pos - 40)
                            val snippetEnd = minOf(responseBody.length, pos + value.length + 40)
                            put("surrounding", responseBody.substring(snippetStart, snippetEnd))
                        }
                        searchFrom = pos + 1
                        occurrenceIndex++
                    }
                }
            }
        }

        return buildJsonObject {
            put("candidates_checked", candidateValues.size)
            put("reflection_count", reflections.size)
            put("reflections", reflections)
        }
    }

    /**
     * Extracts all parameters from an HTTP request: URL query params,
     * body params, cookies, and header values. For JSON bodies, recursively
     * extracts nested keys. For XML bodies, extracts element/attribute values.
     */
    fun extractParams(rawRequest: String): JsonObject {
        val httpRequest = HttpRequest.httpRequest(rawRequest)

        val urlParams = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("URL", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        val bodyParams = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("BODY", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        val cookieParams = buildJsonArray {
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("COOKIE", ignoreCase = true)) {
                    addJsonObject {
                        put("name", param.name())
                        put("value", param.value())
                    }
                }
            }
        }

        val headerParams = buildJsonArray {
            for (header in httpRequest.headers()) {
                addJsonObject {
                    put("name", header.name())
                    put("value", header.value())
                }
            }
        }

        // Attempt to parse JSON body for nested params
        val jsonParams = buildJsonArray {
            val body = httpRequest.bodyToString()
            if (body.isNotEmpty() && (body.trimStart().startsWith("{") || body.trimStart().startsWith("["))) {
                try {
                    val jsonElement = Json.parseToJsonElement(body)
                    flattenJson("", jsonElement, this)
                } catch (_: Exception) {
                    // Not valid JSON, skip
                }
            }
        }

        // Attempt to parse XML body for values
        val xmlParams = buildJsonArray {
            val body = httpRequest.bodyToString()
            if (body.isNotEmpty() && body.trimStart().startsWith("<")) {
                try {
                    extractXmlValues(body, this)
                } catch (_: Exception) {
                    // Not valid XML, skip
                }
            }
        }

        return buildJsonObject {
            put("url_params", urlParams)
            put("body_params", bodyParams)
            put("cookie_params", cookieParams)
            put("header_params", headerParams)
            put("json_params", jsonParams)
            put("xml_params", xmlParams)
            put("total_params",
                urlParams.size + bodyParams.size + cookieParams.size +
                    jsonParams.size + xmlParams.size
            )
        }
    }

    /**
     * Identifies all potential injection/insertion points in a request.
     */
    fun getInsertionPoints(
        rawRequest: String,
        host: String,
        port: Int,
        useTls: Boolean
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        val httpRequest = HttpRequest.httpRequest(httpService, rawRequest)

        val insertionPoints = buildJsonArray {
            // URL parameters
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("URL", ignoreCase = true)) {
                    addJsonObject {
                        put("type", "url_parameter")
                        put("name", param.name())
                        put("value", param.value())
                        put("base_value", param.value())
                    }
                }
            }

            // Body parameters
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("BODY", ignoreCase = true)) {
                    addJsonObject {
                        put("type", "body_parameter")
                        put("name", param.name())
                        put("value", param.value())
                        put("base_value", param.value())
                    }
                }
            }

            // JSON body leaf nodes — Burp's BODY params don't descend into nested JSON,
            // so enumerate each scalar leaf as an insertion point (path notation: a.b[0].c).
            val jsonBody = try { httpRequest.bodyToString() } catch (_: Exception) { "" }
            val contentType = httpRequest.headers().firstOrNull { it.name().equals("Content-Type", true) }?.value() ?: ""
            if (contentType.contains("json", true) || jsonBody.trimStart().startsWith("{") || jsonBody.trimStart().startsWith("[")) {
                for ((jpath, jval) in com.burpmcp.ultra.core.JsonInsertionPoints.leaves(jsonBody)) {
                    addJsonObject {
                        put("type", "json_body")
                        put("name", jpath)
                        put("value", jval)
                        put("base_value", jval)
                    }
                }
            }

            // Cookie parameters
            for (param in httpRequest.parameters()) {
                if (param.type().name.equals("COOKIE", ignoreCase = true)) {
                    addJsonObject {
                        put("type", "cookie")
                        put("name", param.name())
                        put("value", param.value())
                        put("base_value", param.value())
                    }
                }
            }

            // Common injectable headers
            val injectableHeaders = listOf(
                "User-Agent", "Referer", "Origin", "X-Forwarded-For",
                "X-Forwarded-Host", "X-Real-IP", "Accept-Language",
                "Content-Type", "Accept"
            )
            for (header in httpRequest.headers()) {
                if (header.name() in injectableHeaders) {
                    addJsonObject {
                        put("type", "header")
                        put("name", header.name())
                        put("value", header.value())
                        put("base_value", header.value())
                    }
                }
            }

            // URL path segments
            val path = httpRequest.path()
            if (path != null) {
                val segments = path.split("/").filter { it.isNotEmpty() }
                segments.forEachIndexed { idx, segment ->
                    addJsonObject {
                        put("type", "url_path_segment")
                        put("name", "path_segment_$idx")
                        put("value", segment)
                        put("base_value", segment)
                    }
                }
            }
        }

        return buildJsonObject {
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("method", httpRequest.method())
            put("url", httpRequest.url())
            put("insertion_point_count", insertionPoints.size)
            put("insertion_points", insertionPoints)
        }
    }

    /**
     * Compares two requests or two responses, identifying differences in
     * status codes, headers, and body content.
     *
     * @param item1 First raw HTTP request or response.
     * @param item2 Second raw HTTP request or response.
     * @param type "request" or "response".
     */
    fun diff(item1: String, item2: String, type: String): JsonObject {
        return when (type.lowercase()) {
            "request" -> diffRequests(item1, item2)
            "response" -> diffResponses(item1, item2)
            else -> buildJsonObject { put("error", "Invalid type: $type. Must be 'request' or 'response'.") }
        }
    }

    /**
     * Searches response bodies across proxy history for a regex pattern.
     *
     * @param pattern Regex pattern to search for.
     * @param maxResults Maximum number of matching results.
     * @param inScopeOnly Whether to limit search to in-scope items.
     */
    fun searchResponseBodies(pattern: String, maxResults: Int, inScopeOnly: Boolean): JsonObject {
        val regex = try {
            Regex(pattern, RegexOption.IGNORE_CASE)
        } catch (e: Exception) {
            return buildJsonObject { put("error", "Invalid regex: ${e.message}") }
        }

        val proxyHistory = api.proxy().history()
        val matches = buildJsonArray {
            var matchCount = 0
            for (entry in proxyHistory) {
                if (matchCount >= maxResults) break

                try {
                    val req = entry.finalRequest() ?: continue
                    val resp = entry.originalResponse() ?: continue
                    val url = req.url()

                    if (inScopeOnly && !api.scope().isInScope(url)) continue

                    val responseBody = resp.bodyToString()
                    val matchResult = regex.find(responseBody)
                    if (matchResult != null) {
                        addJsonObject {
                            put("url", url)
                            put("method", req.method())
                            put("status_code", resp.statusCode())
                            put("match_value", matchResult.value)
                            put("match_position", matchResult.range.first)
                            // Snippet around the match
                            val snippetStart = maxOf(0, matchResult.range.first - 50)
                            val snippetEnd = minOf(responseBody.length, matchResult.range.last + 51)
                            put("snippet", responseBody.substring(snippetStart, snippetEnd))
                        }
                        matchCount++
                    }
                } catch (_: Exception) {
                    // Skip entries that fail to parse
                }
            }
        }

        return buildJsonObject {
            put("pattern", pattern)
            put("in_scope_only", inScopeOnly)
            put("match_count", matches.size)
            put("max_results", maxResults)
            put("matches", matches)
        }
    }

    /**
     * Auth level diffing: sends the same request with different auth headers and
     * compares responses to detect authorization issues.
     *
     * @param request Base HTTP request string
     * @param host Target host
     * @param port Target port
     * @param useTls Use TLS
     * @param authLevels List of auth level objects, each with: name, header_name, header_value (or "none" for unauthenticated)
     * @param compareFields What to compare: status_code, body, headers, body_length (default: all)
     */
    fun authDiff(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        authLevels: List<JsonObject>,
        compareFields: List<String>?
    ): JsonObject {
        return try {
            val service = HttpService.httpService(host, port, useTls)
            // Normalize request
            val baseRequest = request
                .replace("\\r\\n", "\r\n")
                .replace("\\n", "\n")
                .replace(Regex("(?<!\r)\n"), "\r\n")

            data class AuthResult(
                val levelName: String,
                val statusCode: Int,
                val bodyLength: Int,
                val body: String,
                val headers: Map<String, String>,
                val responseTime: Long
            )

            val results = mutableListOf<AuthResult>()

            val errors = mutableListOf<String>()

            for (level in authLevels) {
                val levelName = level["name"]?.jsonPrimitive?.contentOrNull ?: "unknown"
                val headerName = level["header_name"]?.jsonPrimitive?.contentOrNull
                val headerValue = level["header_value"]?.jsonPrimitive?.contentOrNull

                try {
                    // Build request with this auth level
                    var httpRequest = HttpRequest.httpRequest(service, baseRequest)

                    if (headerName != null && headerValue != null) {
                        // Remove existing auth header and add new one
                        httpRequest = httpRequest.withRemovedHeader(headerName).withHeader(headerName, headerValue)
                    } else if (levelName.equals("none", ignoreCase = true) || levelName.equals("unauth", ignoreCase = true)) {
                        // Remove common auth headers for unauthenticated test
                        httpRequest = httpRequest
                            .withRemovedHeader("Authorization")
                            .withRemovedHeader("Cookie")
                            .withRemovedHeader("X-API-Key")
                            .withRemovedHeader("X-Auth-Token")
                    }

                    val startTime = System.nanoTime()
                    val result = api.http().sendRequest(httpRequest)
                    val elapsed = (System.nanoTime() - startTime) / 1_000_000

                    val resp = result.response()
                    results.add(AuthResult(
                        levelName = levelName,
                        statusCode = resp?.statusCode()?.toInt() ?: 0,
                        bodyLength = resp?.body()?.length() ?: 0,
                        body = resp?.bodyToString() ?: "",
                        headers = resp?.headers()?.associate { it.name() to it.value() } ?: emptyMap(),
                        responseTime = elapsed
                    ))
                } catch (e: Exception) {
                    errors.add("Level '$levelName' failed: ${e.message}")
                }
            }

            // Compare results
            val fields = compareFields ?: listOf("status_code", "body_length", "body", "headers")
            val differences = mutableListOf<JsonObject>()

            // Compare each pair
            for (i in results.indices) {
                for (j in i + 1 until results.size) {
                    val a = results[i]
                    val b = results[j]
                    val diffs = mutableListOf<JsonObject>()

                    if ("status_code" in fields && a.statusCode != b.statusCode) {
                        diffs.add(buildJsonObject {
                            put("field", "status_code")
                            put("${a.levelName}", a.statusCode)
                            put("${b.levelName}", b.statusCode)
                        })
                    }
                    if ("body_length" in fields && a.bodyLength != b.bodyLength) {
                        diffs.add(buildJsonObject {
                            put("field", "body_length")
                            put("${a.levelName}", a.bodyLength)
                            put("${b.levelName}", b.bodyLength)
                            put("length_diff", Math.abs(a.bodyLength - b.bodyLength))
                        })
                    }
                    if ("body" in fields && a.body != b.body) {
                        // Find specific body differences
                        val similarity = calculateSimilarity(a.body, b.body)
                        diffs.add(buildJsonObject {
                            put("field", "body_content")
                            put("similarity_percent", similarity)
                            put("bodies_identical", false)
                        })
                    }
                    if ("headers" in fields) {
                        val diffHeaders = mutableListOf<String>()
                        val allHeaders = (a.headers.keys + b.headers.keys).distinct()
                        for (h in allHeaders) {
                            if (a.headers[h] != b.headers[h]) diffHeaders.add(h)
                        }
                        if (diffHeaders.isNotEmpty()) {
                            diffs.add(buildJsonObject {
                                put("field", "headers")
                                put("different_headers", buildJsonArray { diffHeaders.forEach { add(it) } })
                            })
                        }
                    }

                    if (diffs.isNotEmpty()) {
                        differences.add(buildJsonObject {
                            put("level_a", a.levelName)
                            put("level_b", b.levelName)
                            put("differences", buildJsonArray { diffs.forEach { add(it) } })
                        })
                    }
                }
            }

            // Security analysis
            val statusCodes = results.map { it.statusCode }.distinct()
            val allSameStatus = statusCodes.size == 1
            val allSameBody = results.map { it.body }.distinct().size == 1

            val verdict = AuthDiffVerdict.assess(
                results.map { AuthDiffVerdict.LevelResult(it.levelName, it.statusCode, it.body) }
            ) { x, y -> calculateSimilarity(x, y).toDouble() }

            buildJsonObject {
                put("auth_levels_tested", results.size)
                put("responses", buildJsonArray {
                    results.forEach { r ->
                        add(buildJsonObject {
                            put("level", r.levelName)
                            put("status_code", r.statusCode)
                            put("body_length", r.bodyLength)
                            put("response_time_ms", r.responseTime)
                            put("body_preview", r.body.take(500))
                        })
                    }
                })
                put("differences", buildJsonArray { differences.forEach { add(it) } })
                put("findings", buildJsonArray {
                    verdict.forEach {
                        add(buildJsonObject {
                            put("severity", it.severity)
                            put("id", it.id)
                            put("detail", it.detail)
                        })
                    }
                })
                put("all_same_status", allSameStatus)
                put("all_same_body", allSameBody)
                if (errors.isNotEmpty()) {
                    put("errors", buildJsonArray { errors.forEach { add(it) } })
                }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Auth diff failed: ${e.message}") }
        }
    }

    // ---------------------------------------------------------------
    // Private helper methods
    // ---------------------------------------------------------------

    /**
     * Determines the HTML/JS context surrounding a reflected value.
     */
    private fun determineReflectionContext(body: String, position: Int, length: Int): String {
        // Look at surrounding content to determine context
        val before = body.substring(maxOf(0, position - 200), position)
        val after = body.substring(
            minOf(body.length, position + length),
            minOf(body.length, position + length + 200)
        )

        // Check if inside HTML comment
        val lastCommentOpen = before.lastIndexOf("<!--")
        val lastCommentClose = before.lastIndexOf("-->")
        if (lastCommentOpen > lastCommentClose) {
            return "html_comment"
        }

        // Check if inside <script> block
        val lastScriptOpen = before.lowercase().lastIndexOf("<script")
        val lastScriptClose = before.lowercase().lastIndexOf("</script")
        if (lastScriptOpen > lastScriptClose) {
            // Inside a script tag -- check if in a string
            val lastSingleQuote = before.substring(maxOf(0, lastScriptOpen)).count { it == '\'' } % 2
            val lastDoubleQuote = before.substring(maxOf(0, lastScriptOpen)).count { it == '"' } % 2
            return when {
                lastSingleQuote == 1 -> "javascript_single_quoted_string"
                lastDoubleQuote == 1 -> "javascript_double_quoted_string"
                else -> "javascript"
            }
        }

        // Check if inside <style> block
        val lastStyleOpen = before.lowercase().lastIndexOf("<style")
        val lastStyleClose = before.lowercase().lastIndexOf("</style")
        if (lastStyleOpen > lastStyleClose) {
            return "css"
        }

        // Check if inside an HTML tag attribute
        val lastTagOpen = before.lastIndexOf('<')
        val lastTagClose = before.lastIndexOf('>')
        if (lastTagOpen > lastTagClose) {
            // Inside a tag -- check for attribute context
            val tagContent = before.substring(lastTagOpen)
            val inDoubleQuoteAttr = tagContent.count { it == '"' } % 2 == 1
            val inSingleQuoteAttr = tagContent.count { it == '\'' } % 2 == 1
            return when {
                inDoubleQuoteAttr -> "html_attribute_double_quoted"
                inSingleQuoteAttr -> "html_attribute_single_quoted"
                tagContent.contains("=") -> "html_attribute_unquoted"
                else -> "html_tag"
            }
        }

        // Check if it looks like a URL context
        val urlPatterns = listOf("href=", "src=", "action=", "url(", "location")
        for (pattern in urlPatterns) {
            if (before.lowercase().endsWith(pattern) ||
                before.lowercase().endsWith("$pattern\"") ||
                before.lowercase().endsWith("$pattern'")
            ) {
                return "url"
            }
        }

        return "html_body"
    }

    /**
     * Recursively flattens a JSON element into dot-notation key-value pairs.
     */
    private fun flattenJson(prefix: String, element: JsonElement, builder: JsonArrayBuilder) {
        when (element) {
            is JsonObject -> {
                for ((key, value) in element) {
                    val newPrefix = if (prefix.isEmpty()) key else "$prefix.$key"
                    flattenJson(newPrefix, value, builder)
                }
            }
            is JsonArray -> {
                element.forEachIndexed { idx, value ->
                    flattenJson("$prefix[$idx]", value, builder)
                }
            }
            is JsonPrimitive -> {
                builder.addJsonObject {
                    put("name", prefix)
                    put("value", element.content)
                    put("type", when {
                        element.isString -> "string"
                        element.booleanOrNull != null -> "boolean"
                        element.longOrNull != null -> "number"
                        element.doubleOrNull != null -> "number"
                        else -> "unknown"
                    })
                }
            }
        }
    }

    /**
     * Basic XML value extraction using regex patterns (avoids requiring
     * an XML parser dependency). Extracts element text content and
     * attribute values.
     */
    private fun extractXmlValues(xml: String, builder: JsonArrayBuilder) {
        // Extract attribute values: name="value"
        val attrRegex = Regex("""(\w+)\s*=\s*"([^"]*?)"""")
        for (match in attrRegex.findAll(xml)) {
            builder.addJsonObject {
                put("name", "attr:${match.groupValues[1]}")
                put("value", match.groupValues[2])
                put("type", "attribute")
            }
        }

        // Extract element text content: <tag>value</tag>
        val elementRegex = Regex("""<(\w+)[^>]*>([^<]+)</\1>""")
        for (match in elementRegex.findAll(xml)) {
            val text = match.groupValues[2].trim()
            if (text.isNotEmpty()) {
                builder.addJsonObject {
                    put("name", "element:${match.groupValues[1]}")
                    put("value", text)
                    put("type", "element_text")
                }
            }
        }
    }

    /**
     * Compares two raw HTTP requests.
     */
    private fun diffRequests(raw1: String, raw2: String): JsonObject {
        val req1 = HttpRequest.httpRequest(raw1)
        val req2 = HttpRequest.httpRequest(raw2)

        val headerDiffs = diffHeaders(
            req1.headers().associate { it.name() to it.value() },
            req2.headers().associate { it.name() to it.value() }
        )

        val paramDiffs = buildJsonArray {
            val params1 = req1.parameters().associate { "${it.type().name}:${it.name()}" to it.value() }
            val params2 = req2.parameters().associate { "${it.type().name}:${it.name()}" to it.value() }
            val allKeys = params1.keys + params2.keys
            for (key in allKeys) {
                val v1 = params1[key]
                val v2 = params2[key]
                if (v1 != v2) {
                    addJsonObject {
                        put("parameter", key)
                        put("item1_value", v1 ?: "(absent)")
                        put("item2_value", v2 ?: "(absent)")
                        put("change", when {
                            v1 == null -> "added"
                            v2 == null -> "removed"
                            else -> "modified"
                        })
                    }
                }
            }
        }

        val body1 = req1.bodyToString()
        val body2 = req2.bodyToString()
        val bodySimilarity = calculateSimilarity(body1, body2)

        return buildJsonObject {
            put("type", "request")
            put("method_match", req1.method() == req2.method())
            put("item1_method", req1.method())
            put("item2_method", req2.method())
            put("path_match", req1.path() == req2.path())
            put("item1_path", req1.path())
            put("item2_path", req2.path())
            put("header_differences", headerDiffs)
            put("parameter_differences", paramDiffs)
            put("body_match", body1 == body2)
            put("body_similarity_percent", bodySimilarity)
            put("item1_body_length", body1.length)
            put("item2_body_length", body2.length)
        }
    }

    /**
     * Compares two raw HTTP responses.
     */
    private fun diffResponses(raw1: String, raw2: String): JsonObject {
        val resp1 = HttpResponse.httpResponse(raw1)
        val resp2 = HttpResponse.httpResponse(raw2)

        val headerDiffs = diffHeaders(
            resp1.headers().associate { it.name() to it.value() },
            resp2.headers().associate { it.name() to it.value() }
        )

        val body1 = resp1.bodyToString()
        val body2 = resp2.bodyToString()
        val bodySimilarity = calculateSimilarity(body1, body2)

        return buildJsonObject {
            put("type", "response")
            put("status_code_match", resp1.statusCode() == resp2.statusCode())
            put("item1_status_code", resp1.statusCode())
            put("item2_status_code", resp2.statusCode())
            put("header_differences", headerDiffs)
            put("body_match", body1 == body2)
            put("body_similarity_percent", bodySimilarity)
            put("item1_body_length", body1.length)
            put("item2_body_length", body2.length)
            put("item1_mime_type", resp1.statedMimeType()?.toString() ?: "unknown")
            put("item2_mime_type", resp2.statedMimeType()?.toString() ?: "unknown")
        }
    }

    /**
     * Compares two header maps and produces an array of differences.
     */
    private fun diffHeaders(
        headers1: Map<String, String>,
        headers2: Map<String, String>
    ): JsonArray {
        return buildJsonArray {
            val allKeys = headers1.keys + headers2.keys
            for (key in allKeys) {
                val v1 = headers1[key]
                val v2 = headers2[key]
                if (v1 != v2) {
                    addJsonObject {
                        put("header", key)
                        put("item1_value", v1 ?: "(absent)")
                        put("item2_value", v2 ?: "(absent)")
                        put("change", when {
                            v1 == null -> "added"
                            v2 == null -> "removed"
                            else -> "modified"
                        })
                    }
                }
            }
        }
    }

    /**
     * Calculates a rough similarity percentage between two strings using
     * character-level bigram overlap (Dice coefficient).
     */
    private fun calculateSimilarity(s1: String, s2: String): Double {
        if (s1 == s2) return 100.0
        if (s1.isEmpty() && s2.isEmpty()) return 100.0
        if (s1.isEmpty() || s2.isEmpty()) return 0.0

        val bigrams1 = s1.zipWithNext().toSet()
        val bigrams2 = s2.zipWithNext().toSet()
        val intersection = bigrams1.intersect(bigrams2).size
        val total = bigrams1.size + bigrams2.size

        if (total == 0) return 100.0
        return Math.round((2.0 * intersection / total) * 10000.0) / 100.0
    }
}
