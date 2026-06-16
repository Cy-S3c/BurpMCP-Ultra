package com.burpmcp.ultra.webprobe

/**
 * Pure CORS verdict from a sent Origin and the response's
 * Access-Control-Allow-Origin / -Allow-Credentials headers.
 */
object CorsAnalysis {
    data class Verdict(val severity: String, val id: String, val detail: String)

    fun assess(sentOrigin: String, acao: String?, acac: String?): Verdict? {
        if (acao == null) return null
        val creds = acac?.equals("true", ignoreCase = true) == true
        return when {
            // Check the null origin first: "null" == "null" is technically a reflection,
            // but it is its own (distinct, attacker-reachable) misconfiguration.
            acao.equals("null", ignoreCase = true) && sentOrigin.equals("null", ignoreCase = true) -> Verdict(
                "high", "null_origin_allowed",
                "ACAO allows the 'null' origin — reachable from sandboxed iframes / data: URLs; with credentials this is exploitable."
            )
            acao == sentOrigin && creds -> Verdict(
                "critical", "reflected_origin_with_creds",
                "ACAO reflects the request Origin AND ACAC=true — any site can read authenticated responses (account takeover / data theft)."
            )
            acao == sentOrigin -> Verdict(
                "high", "reflected_origin",
                "ACAO reflects the request Origin (no credentials) — any site can read this response cross-origin."
            )
            acao == "*" && creds -> Verdict(
                "medium", "wildcard_with_creds",
                "ACAO=* together with ACAC=true is an invalid/over-permissive combination; some non-browser clients honor it."
            )
            acao == "*" -> Verdict(
                "low", "wildcard",
                "ACAO=* — wildcard CORS without credentials; acceptable only for genuinely public data."
            )
            else -> null
        }
    }
}
