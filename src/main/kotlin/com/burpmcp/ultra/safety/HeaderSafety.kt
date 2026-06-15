package com.burpmcp.ultra.safety

/**
 * Validation for rule-driven header writes. Match/replace and traffic rules let
 * the agent add headers to *live* traffic; without a CR/LF check a value like
 * `ok\r\nInjected: 1` becomes header/request injection into the wire. Every
 * rule-applied header must pass through here first.
 */
object HeaderSafety {

    /** True if the string contains a CR or LF (i.e. could break out of a header line). */
    fun containsCrlf(s: String): Boolean = s.contains('\r') || s.contains('\n')

    /** A header name must be non-empty, CRLF-free, and contain no colon. */
    fun isValidHeaderName(name: String): Boolean =
        name.isNotEmpty() && !containsCrlf(name) && !name.contains(':')

    /** A header value must be CRLF-free. */
    fun isValidHeaderValue(value: String): Boolean = !containsCrlf(value)

    /**
     * Parses a `Name: Value` line, splitting on the first colon and trimming
     * both sides. Returns null if there is no colon or if the resulting name or
     * value is invalid (e.g. embeds CRLF).
     */
    fun parseHeaderLine(line: String): Pair<String, String>? {
        val idx = line.indexOf(':')
        if (idx <= 0) return null
        val name = line.substring(0, idx).trim()
        val value = line.substring(idx + 1).trim()
        if (!isValidHeaderName(name) || !isValidHeaderValue(value)) return null
        return name to value
    }
}
