package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burpmcp.ultra.recon.JsEndpoints
import com.burpmcp.ultra.recon.ReconHeuristics
import com.burpmcp.ultra.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Reconnaissance/discovery — the capability gap that left the agent only able to
 * test endpoints it was explicitly handed. Provides JS endpoint harvesting,
 * wordlist content discovery (with soft-404 calibration), and reflected-param
 * mining. Active probes respect the operator scope policy.
 */
class ReconBridge(private val api: MontoyaApi) {

    private companion object {
        const val MARKER = "zZmcpR3c0nMk7Qx"
        const val CALIBRATION_PATH = "/zzz_mcp_recon_calibration_404page"
    }

    private val scopeGate = ScopeGate(api)

    /** GET [url], returning (status, bodyLength); (0,0) on failure. */
    private fun sendGet(url: String): Pair<Int, Int> = try {
        val resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response()
        Pair(resp?.statusCode()?.toInt() ?: 0, resp?.body()?.length() ?: 0)
    } catch (_: Exception) {
        Pair(0, 0)
    }

    /** Harvest endpoint paths/URLs from JavaScript responses already in proxy history. */
    fun jsEndpoints(maxItems: Int, hostFilter: String?): JsonObject {
        return try {
            var items = api.proxy().history().toList()
            if (hostFilter != null) {
                val rx = Regex(hostFilter, RegexOption.IGNORE_CASE)
                items = items.filter { try { rx.containsMatchIn(it.finalRequest().httpService().host()) } catch (_: Exception) { false } }
            }
            items = items.takeLast(maxItems.coerceIn(1, 2000))
            val endpoints = linkedSetOf<String>()
            var scanned = 0
            for (item in items) {
                val url = try { item.finalRequest().url() } catch (_: Exception) { "" }
                val isJs = url.substringBefore('?').endsWith(".js", true) || try {
                    item.hasResponse() && (item.originalResponse().headerValue("Content-Type")?.contains("javascript", true) == true)
                } catch (_: Exception) { false }
                if (!isJs) continue
                scanned++
                val body = try { if (item.hasResponse()) item.originalResponse().bodyToString() else "" } catch (_: Exception) { "" }
                endpoints.addAll(JsEndpoints.extract(body))
            }
            buildJsonObject {
                put("js_responses_scanned", scanned)
                put("endpoint_count", endpoints.size)
                put("endpoints", buildJsonArray { endpoints.take(2000).forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "JS endpoint scan failed: ${e.message}") }
        }
    }

    /** Brute a wordlist of [paths] under [baseUrl], calibrating against a known-missing path to filter soft-404s. */
    fun contentDiscovery(baseUrl: String, paths: List<String>): JsonObject {
        return try {
            val base = baseUrl.trimEnd('/')
            val baseCheck = scopeGate.check("$base/")
            baseCheck.deny?.let { return it }
            val (calStatus, calLen) = sendGet(base + CALIBRATION_PATH)
            val tested = paths.take(2000)
            val found = mutableListOf<JsonObject>()
            var skippedOutOfScope = 0
            for (path in tested) {
                val full = base + (if (path.startsWith("/")) path else "/$path")
                // Per-path scope check: Burp scope can exclude specific paths under an in-scope host.
                if (scopeGate.deny(full) != null) { skippedOutOfScope++; continue }
                val (status, len) = sendGet(full)
                if (ReconHeuristics.isInteresting(calStatus, calLen, status, len)) {
                    found.add(buildJsonObject { put("path", path); put("url", full); put("status", status); put("length", len) })
                }
            }
            buildJsonObject {
                put("base_url", base)
                baseCheck.warning?.let { put("scope_warning", it) }
                put("calibration", buildJsonObject { put("status", calStatus); put("length", calLen) })
                put("tested", tested.size)
                if (skippedOutOfScope > 0) put("skipped_out_of_scope", skippedOutOfScope)
                put("found_count", found.size)
                put("found", buildJsonArray { found.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Content discovery failed: ${e.message}") }
        }
    }

    /** Probe [candidates] as query params on [url], flagging those reflected in the response (injection candidates). */
    fun paramMine(url: String, candidates: List<String>): JsonObject {
        return try {
            val check = scopeGate.check(url)
            check.deny?.let { return it }
            val sep = if (url.contains("?")) "&" else "?"
            val tested = candidates.take(1000)
            val reflected = mutableListOf<JsonObject>()
            for (cand in tested) {
                val testUrl = "$url$sep$cand=$MARKER"
                val body = try {
                    api.http().sendRequest(HttpRequest.httpRequestFromUrl(testUrl)).response()?.bodyToString() ?: ""
                } catch (_: Exception) { "" }
                if (ReconHeuristics.reflects(body, MARKER)) {
                    reflected.add(buildJsonObject { put("param", cand); put("reflected", true); put("url", testUrl) })
                }
            }
            buildJsonObject {
                put("url", url)
                check.warning?.let { put("scope_warning", it) }
                put("marker", MARKER)
                put("tested", tested.size)
                put("reflected_count", reflected.size)
                put("reflected_params", buildJsonArray { reflected.forEach { add(it) } })
                put("note", "Reflected params are candidate injection points (XSS/SSRF/IDOR). Behavioral-diff mining (params that change the response without reflecting) is a follow-up.")
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Param mining failed: ${e.message}") }
        }
    }
}
