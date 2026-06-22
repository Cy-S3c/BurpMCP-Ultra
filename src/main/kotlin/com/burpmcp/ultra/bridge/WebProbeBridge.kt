package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burpmcp.ultra.safety.ScopeGate
import com.burpmcp.ultra.webprobe.CorsAnalysis
import com.burpmcp.ultra.webprobe.Fingerprint
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Quick web-misconfig recon: CORS policy probing and tech/WAF fingerprinting. Scope-gated. */
class WebProbeBridge(private val api: MontoyaApi) {

    private val scopeGate = ScopeGate(api)

    /** Probes CORS by sending crafted Origin headers and classifying the ACAO/ACAC response. */
    fun corsProbe(url: String): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        return try {
            val origins = listOf("https://evil-mcp-probe.example", "null")
            var anyVuln = false
            val tests = buildJsonArray {
                for (origin in origins) {
                    val resp = try {
                        api.http().sendRequest(HttpRequest.httpRequestFromUrl(url).withAddedHeader("Origin", origin)).response()
                    } catch (_: Exception) { null }
                    val acao = resp?.headerValue("Access-Control-Allow-Origin")
                    val acac = resp?.headerValue("Access-Control-Allow-Credentials")
                    val verdict = CorsAnalysis.assess(origin, acao, acac)
                    if (verdict != null) anyVuln = true
                    add(buildJsonObject {
                        put("origin", origin)
                        put("acao", acao)
                        put("acac", acac)
                        if (verdict != null) {
                            put("severity", verdict.severity)
                            put("id", verdict.id)
                            put("detail", verdict.detail)
                        }
                    })
                }
            }
            buildJsonObject {
                put("url", url)
                check.warning?.let { put("scope_warning", it) }
                put("vulnerable", anyVuln)
                put("tests", tests)
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "CORS probe failed: ${e.message}") }
        }
    }

    /** Fingerprints tech / WAF / framework from a single GET. */
    fun fingerprint(url: String): JsonObject {
        val check = scopeGate.check(url)
        check.deny?.let { return it }
        return try {
            val resp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)).response()
                ?: return buildJsonObject { put("error", "No response from $url") }
            val headers = resp.headers().groupBy({ it.name().lowercase() }, { it.value() }).mapValues { it.value.joinToString("; ") }
            val body = try { resp.bodyToString() } catch (_: Exception) { "" }
            val techs = Fingerprint.detect(headers, body)
            buildJsonObject {
                put("url", url)
                check.warning?.let { put("scope_warning", it) }
                put("status", resp.statusCode().toInt())
                put("technologies", buildJsonArray { techs.forEach { add(it) } })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Fingerprint failed: ${e.message}") }
        }
    }
}
