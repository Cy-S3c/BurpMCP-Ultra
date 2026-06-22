package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Batch broken-access-control / IDOR testing: replays each request under every
 * identity and flags where a lower-privilege or unauthenticated identity gets a
 * response matching a higher-privilege one. Scales auth_diff (single request)
 * across many endpoints in one call, reusing AnalysisBridge.authDiff (which is
 * scope-gated and applies the AuthDiffVerdict logic).
 */
class AccessControlBridge(api: MontoyaApi) {

    private val analysis = AnalysisBridge(api)

    fun sweep(requests: List<JsonObject>, identities: List<JsonObject>): JsonObject {
        if (requests.isEmpty() || identities.size < 2) {
            return buildJsonObject {
                put("error", "Provide 'requests' (>=1) and 'identities' (>=2, e.g. an authed identity plus a 'none' identity).")
            }
        }

        val results = requests.mapIndexed { idx, r ->
            val raw = r["raw_request"]?.jsonPrimitive?.contentOrNull
            val host = r["host"]?.jsonPrimitive?.contentOrNull
            if (raw == null || host == null) {
                buildJsonObject { put("request_index", idx); put("error", "each request needs 'raw_request' and 'host'") }
            } else {
                val port = r["port"]?.jsonPrimitive?.intOrNull ?: 443
                val tls = r["use_tls"]?.jsonPrimitive?.booleanOrNull ?: (port == 443)
                val diff = analysis.authDiff(raw, host, port, tls, identities, null)
                buildJsonObject {
                    put("request_index", idx)
                    put("target", "${if (tls) "https" else "http"}://$host:$port")
                    diff["error"]?.let { put("error", it) }
                    diff["out_of_scope"]?.let { put("out_of_scope", it) }
                    (diff["findings"] as? JsonArray)?.let { put("findings", it) }
                    (diff["responses"] as? JsonArray)?.let { put("responses", it) }
                }
            }
        }

        val flagged = results.count { entry ->
            (entry["findings"] as? JsonArray)?.any { f ->
                val sev = f.jsonObject["severity"]?.jsonPrimitive?.contentOrNull
                sev == "critical" || sev == "high"
            } == true
        }

        return buildJsonObject {
            put("requests_tested", requests.size)
            put("identities", identities.size)
            put("requests_with_broken_access_control", flagged)
            put("results", buildJsonArray { results.forEach { add(it) } })
            put("note", "Each request is replayed under every identity; 'findings' per request flag where a lower-privilege/unauth identity gets a response matching a higher-privilege one (broken access control / IDOR).")
        }
    }
}
