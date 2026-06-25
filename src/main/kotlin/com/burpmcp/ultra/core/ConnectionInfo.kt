package com.burpmcp.ultra.core

/**
 * Single source of truth for how MCP clients connect to BurpMCP-Ultra. Used by the
 * dashboard, the Server UI tab (and mirrored in the README/configs) so the connection
 * details can never drift again.
 *
 * Two invariants this guards, both of which previously broke clients (GitHub issue #1):
 *  1. The MCP SSE endpoint is the **root path `/`**, NOT `/sse`.
 *  2. A **bearer token is required** on every request.
 */
object ConnectionInfo {
    const val PRIMARY_PORT = 9876
    const val SECONDARY_PORT = 9877
    const val DASHBOARD_PORT = 9878

    /** Shown where the real token must NOT be embedded (e.g. browser-served HTML). */
    const val TOKEN_PLACEHOLDER = "PASTE_TOKEN_FROM_SERVER_TAB"

    /** The MCP SSE endpoint URL for [port] — the ROOT path `/`, never `/sse`. */
    fun sseUrl(port: Int): String = "http://127.0.0.1:$port/"

    val primarySseUrl: String get() = sseUrl(PRIMARY_PORT)
    val secondarySseUrl: String get() = sseUrl(SECONDARY_PORT)
    val dashboardUrl: String get() = "http://127.0.0.1:$DASHBOARD_PORT"

    /**
     * A ready-to-paste MCP client config. Pass the real [token] ONLY for same-process
     * surfaces (the Swing Server tab). Pass `null` for anything browser-served so the
     * token is not embedded in HTML — the user then fills [TOKEN_PLACEHOLDER] from the
     * Server tab (this preserves the dashboard's HttpOnly-cookie token confidentiality).
     */
    fun clientConfigJson(token: String?, port: Int = PRIMARY_PORT): String {
        val bearer = token ?: TOKEN_PLACEHOLDER
        return """{"mcpServers":{"burp":{"type":"sse","url":"${sseUrl(port)}","headers":{"Authorization":"Bearer $bearer"}}}}"""
    }
}
