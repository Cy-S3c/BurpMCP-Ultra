package com.burpmcp.ultra.core

/**
 * Default redaction of credential-bearing request headers in `proxy_history` /
 * `proxy_history_search` output (GitHub issue #20, reported by **@bananacake0**).
 *
 * `request_headers` used to be serialized unconditionally with full values, so a live
 * `Cookie` / `Authorization` entered the LLM's context on an ordinary recon query — with no
 * way to opt out short of avoiding history search entirely. Now header *names* (and the shape
 * of the header set) are always preserved for recon, while the *values* of sensitive headers
 * are masked unless the caller explicitly asked for request material via `include_request=true`
 * (which returns the full raw request text anyway, so no capability is lost).
 */
object SensitiveHeaders {

    /** Header names (lowercase, exact) whose values are credentials or session secrets. */
    val NAMES: Set<String> = setOf(
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-session-token",
        "x-amz-security-token",
        "x-csrf-token",
        "x-xsrf-token"
    )

    const val REDACTED = "<redacted>"

    fun isSensitive(name: String): Boolean = name.trim().lowercase() in NAMES

    /**
     * Value to emit for a header: masked when [name] is sensitive and the caller did not
     * explicitly request full request material ([reveal]); verbatim otherwise.
     */
    fun value(name: String, value: String, reveal: Boolean): String =
        if (!reveal && isSensitive(name)) REDACTED else value
}
