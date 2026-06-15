package com.burpmcp.ultra.safety

/**
 * Operator-controlled enforcement level for outbound requests the agent asks
 * Burp to send. Persisted in Burp preferences (key `mcp_scope_mode`); the agent
 * cannot change it. Default is [WARN] so existing workflows keep working while
 * out-of-scope sends are flagged; an operator can harden to [ENFORCE].
 */
enum class ScopeMode {
    /** No scope checking (legacy behaviour). */
    OFF,
    /** Out-of-scope sends are allowed but flagged in the response + audit log. */
    WARN,
    /** Out-of-scope sends are blocked. */
    ENFORCE;

    companion object {
        fun fromString(s: String?): ScopeMode = when (s?.trim()?.uppercase()) {
            "OFF" -> OFF
            "ENFORCE" -> ENFORCE
            "WARN" -> WARN
            else -> WARN
        }
    }
}

/** The outcome of a [ScopePolicy] evaluation for a single outbound request. */
enum class ScopeDecision { ALLOW, WARN, DENY }

/**
 * Pure decision function mapping (mode, in-scope?) → action. Kept free of the
 * Montoya API so it is unit-testable; callers supply `inScope` from
 * `api.scope().isInScope(url)`.
 */
object ScopePolicy {
    fun decide(mode: ScopeMode, inScope: Boolean): ScopeDecision = when (mode) {
        ScopeMode.OFF -> ScopeDecision.ALLOW
        ScopeMode.WARN -> if (inScope) ScopeDecision.ALLOW else ScopeDecision.WARN
        ScopeMode.ENFORCE -> if (inScope) ScopeDecision.ALLOW else ScopeDecision.DENY
    }
}
