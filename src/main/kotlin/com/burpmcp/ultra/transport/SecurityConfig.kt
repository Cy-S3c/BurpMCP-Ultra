package com.burpmcp.ultra.transport

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Localhost security hardening for the embedded Ktor servers.
 *
 * Binding to `127.0.0.1` is NOT a trust boundary: any web page the operator
 * visits can issue requests to localhost, and DNS rebinding can make those
 * responses cross-origin-readable. Three independent controls close that hole:
 *
 *  1. **Host-header allowlist** — defeats DNS rebinding. A rebound request
 *     carries `Host: attacker.com`, which is not on the allowlist and is rejected
 *     before any handler runs.
 *  2. **Origin lockdown** — rejects any cross-origin browser request outright
 *     (and CORS only ever advertises the loopback origins).
 *  3. **Per-session bearer/query token** — only a caller holding the token
 *     (surfaced solely in the local Burp UI) may invoke anything.
 *
 * Removing any one of these re-opens the "malicious website drives your local
 * MCP server" chain, so all three are installed together.
 */
object SecurityConfig {
    /** Generates a fresh 256-bit URL-safe session token. */
    fun generateToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

/**
 * Installs Host validation + locked CORS + token auth on this [Application].
 *
 * @param token the per-session secret required on every request.
 * @param ports loopback ports that define the valid Host / Origin allowlist.
 * @param tokenExemptPaths paths served WITHOUT a token (still Host/Origin-checked).
 *   Used only for the dashboard's `/` page, which injects the token into the
 *   served HTML so its own same-origin API calls can authenticate. A cross-origin
 *   attacker cannot read that page (same-origin policy) and cannot reach it via
 *   rebinding (Host check), so the token stays confidential.
 */
fun Application.installLocalhostSecurity(
    token: String,
    ports: List<Int>,
    tokenExemptPaths: Set<String> = emptySet()
) {
    val allowedHosts = ports.flatMap { listOf("127.0.0.1:$it", "localhost:$it") }.toSet()
    val allowedOrigins = ports.flatMap {
        listOf("http://127.0.0.1:$it", "http://localhost:$it")
    }.toSet()

    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        allowNonSimpleContentTypes = true
        // Only loopback origins are ever permitted — never anyHost().
        ports.forEach { p ->
            allowHost("127.0.0.1:$p", schemes = listOf("http"))
            allowHost("localhost:$p", schemes = listOf("http"))
        }
    }

    intercept(ApplicationCallPipeline.ApplicationPhase.Plugins) {
        // CORS preflight must pass through without auth so legitimate browsers work.
        if (call.request.httpMethod == HttpMethod.Options) return@intercept

        // 1. Host-header allowlist — primary anti-DNS-rebinding control.
        val host = call.request.headers[HttpHeaders.Host]
        if (host == null || host !in allowedHosts) {
            call.respondText(
                """{"error":"forbidden: invalid Host header"}""",
                ContentType.Application.Json,
                HttpStatusCode.Forbidden
            )
            return@intercept finish()
        }

        // 2. Origin lockdown — reject cross-origin browser requests outright.
        val origin = call.request.headers[HttpHeaders.Origin]
        if (origin != null && origin !in allowedOrigins) {
            call.respondText(
                """{"error":"forbidden: cross-origin request rejected"}""",
                ContentType.Application.Json,
                HttpStatusCode.Forbidden
            )
            return@intercept finish()
        }

        // 3. Token — required on everything except explicitly exempt paths.
        if (call.request.path() !in tokenExemptPaths) {
            val provided = call.request.headers[HttpHeaders.Authorization]
                ?.removePrefix("Bearer ")?.trim()
                ?: call.request.cookies["mcp_token"]
                ?: call.request.queryParameters["token"]
            if (provided == null || !constantTimeEquals(provided, token)) {
                call.respondText(
                    """{"error":"unauthorized: missing or invalid token"}""",
                    ContentType.Application.Json,
                    HttpStatusCode.Unauthorized
                )
                return@intercept finish()
            }
        }
    }
}

/** Length-constant string comparison to avoid token timing side-channels. */
private fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
