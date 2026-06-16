package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burpmcp.ultra.graphql.GraphQl
import com.burpmcp.ultra.safety.ScopeDecision
import com.burpmcp.ultra.safety.ScopeMode
import com.burpmcp.ultra.safety.ScopePolicy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * GraphQL security recon: introspection enumeration and, when introspection is
 * disabled, "Did you mean" field-suggestion enumeration. Scope-gated.
 */
class GraphQlBridge(private val api: MontoyaApi) {

    private fun scopeBlocked(url: String): Boolean {
        val mode = ScopeMode.fromString(
            try { api.persistence().preferences().getString("mcp_scope_mode") } catch (_: Exception) { null }
        )
        if (mode == ScopeMode.OFF) return false
        val inScope = try { api.scope().isInScope(url) } catch (_: Exception) { return false }
        return ScopePolicy.decide(mode, inScope) == ScopeDecision.DENY
    }

    fun probe(url: String): JsonObject {
        if (scopeBlocked(url)) {
            return buildJsonObject {
                put("error", "Blocked by scope policy (mcp_scope_mode=enforce): $url is not in Burp's target scope.")
                put("out_of_scope", true)
            }
        }
        return try {
            val introBody = postQuery(url, GraphQl.INTROSPECTION_QUERY)
            val introJson = try { Json.parseToJsonElement(introBody).jsonObject } catch (_: Exception) { null }

            if (introJson?.get("data")?.jsonObject?.get("__schema") != null) {
                buildJsonObject {
                    put("endpoint", url)
                    put("introspection", GraphQl.summarize(introJson))
                    put("note", "Introspection is ENABLED — full schema disclosed; enumerate mutations for high-impact operations.")
                }
            } else {
                val badBody = postQuery(url, "query { zzNonexistentField_mcp1234 }")
                val suggestions = extractErrorMessages(badBody).flatMap { GraphQl.extractSuggestions(it) }
                buildJsonObject {
                    put("endpoint", url)
                    put("introspection", buildJsonObject { put("introspection_enabled", false) })
                    put("field_suggestions_enabled", suggestions.isNotEmpty())
                    put("suggestions", buildJsonArray { suggestions.forEach { add(it) } })
                    put(
                        "note",
                        if (suggestions.isNotEmpty())
                            "Introspection disabled, but field suggestions leak schema — enumerate fields via 'Did you mean'."
                        else
                            "Introspection disabled and no field suggestions detected."
                    )
                }
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "GraphQL probe failed: ${e.message}") }
        }
    }

    private fun postQuery(url: String, query: String): String {
        return try {
            val body = buildJsonObject { put("query", query) }.toString()
            val req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/json")
                .withBody(body)
            api.http().sendRequest(req).response()?.bodyToString() ?: ""
        } catch (_: Exception) { "" }
    }

    private fun extractErrorMessages(body: String): List<String> = try {
        Json.parseToJsonElement(body).jsonObject["errors"]?.jsonArray
            ?.mapNotNull { it.jsonObject["message"]?.jsonPrimitive?.contentOrNull } ?: emptyList()
    } catch (_: Exception) { emptyList() }
}
