package com.burpmcp.ultra.safety

import burp.api.montoya.MontoyaApi
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Centralized operator-controlled outbound scope gate, shared by EVERY bridge
 * that sends requests (HTTP send/raw/chain/parallel/fuzz/race, recon, graphql,
 * webprobe). Reads the persisted enforcement mode (`mcp_scope_mode`); the agent
 * cannot change it.
 *
 * This replaces several per-bridge copies of the same logic that had drifted out
 * of sync — some send paths were ungated (ENFORCE bypassable via batch/chain/
 * fuzz/race tools), and the recon/graphql/webprobe bridges never surfaced the
 * WARN-mode flag. Funnelling every send through this one place keeps the policy
 * uniform and means a future send path cannot silently skip the gate.
 *
 * Fails open (allows) when scope cannot be evaluated, so a Burp quirk never
 * blocks legitimate work.
 */
class ScopeGate(private val api: MontoyaApi) {

    /** Outcome of a check: [deny] is a ready-to-return error object (block the send); [warning] annotates an allowed-but-out-of-scope send. */
    data class Check(val deny: JsonObject?, val warning: String?)

    private fun mode(): ScopeMode = ScopeMode.fromString(
        try { api.persistence().preferences().getString("mcp_scope_mode") } catch (_: Exception) { null }
    )

    fun check(url: String): Check {
        val m = mode()
        if (m == ScopeMode.OFF) return Check(null, null)
        val inScope = try { api.scope().isInScope(url) } catch (_: Exception) { return Check(null, null) }
        return when (ScopePolicy.decide(m, inScope)) {
            ScopeDecision.DENY -> Check(denyJson(url), null)
            ScopeDecision.WARN -> Check(null, "out_of_scope: $url is not in Burp's target scope")
            ScopeDecision.ALLOW -> Check(null, null)
        }
    }

    /** Convenience: the deny object if [url] must be blocked under ENFORCE, else null. */
    fun deny(url: String): JsonObject? = check(url).deny

    companion object {
        fun denyJson(url: String): JsonObject = buildJsonObject {
            put(
                "error",
                "Blocked by scope policy: target is not in Burp's scope. An operator can allow it by adding it to " +
                    "Burp's target scope or setting preference mcp_scope_mode to 'warn' or 'off'."
            )
            put("out_of_scope", true)
            put("url", url)
            put("scope_mode", "enforce")
        }
    }
}
