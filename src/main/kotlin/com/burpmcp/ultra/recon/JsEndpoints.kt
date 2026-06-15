package com.burpmcp.ultra.recon

/**
 * Extracts endpoint paths and URLs from JavaScript source. SPAs expose much of
 * their API surface in JS, so harvesting it from proxy history surfaces routes
 * the agent was never explicitly handed.
 */
object JsEndpoints {
    private val quotedPath = Regex("""["'`](/[A-Za-z0-9_\-./]+(?:\?[A-Za-z0-9_\-.=&%]*)?)["'`]""")
    private val urlPattern = Regex("""https?://[A-Za-z0-9._\-]+(?::[0-9]+)?(?:/[A-Za-z0-9_\-./?=&%#]*)?""")

    fun extract(text: String): Set<String> {
        val out = linkedSetOf<String>()
        quotedPath.findAll(text).forEach { m ->
            val p = m.groupValues[1]
            if (!p.startsWith("//")) out.add(p) // drop protocol-relative noise
        }
        urlPattern.findAll(text).forEach { out.add(it.value) }
        return out
    }
}
