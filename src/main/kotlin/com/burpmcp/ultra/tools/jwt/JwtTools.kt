package com.burpmcp.ultra.tools.jwt

import com.burpmcp.ultra.bridge.JwtBridge
import com.burpmcp.ultra.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the `jwt_attack` MCP tool — offensive JWT operations far beyond the
 * decode-only `util_jwt_decode`.
 */
object JwtTools {
    fun register(server: Server, bridge: JwtBridge) {
        server.addTool(
            name = "jwt_attack",
            description = "Attack or analyze a JSON Web Token. Modes: " +
                "analyze (flag alg:none, weak/asymmetric alg, kid/jku, missing exp); " +
                "forge_none (forge unsigned tokens, case variants); " +
                "alg_confusion (RS256->HS256 key confusion — pass the server's public_key); " +
                "crack (recover the HMAC secret from a wordlist or built-in list); " +
                "sign (re-sign with a known secret + payload_overrides, e.g. after cracking). " +
                "Use for auth bypass / privilege escalation testing.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("token") { put("type", "string"); put("description", "The JWT to operate on") }
                    putJsonObject("mode") { put("type", "string"); put("description", "analyze|forge_none|alg_confusion|crack|sign (default: analyze)") }
                    putJsonObject("secret") { put("type", "string"); put("description", "HMAC secret for mode=sign") }
                    putJsonObject("public_key") { put("type", "string"); put("description", "Server public key text (e.g. PEM) for mode=alg_confusion") }
                    putJsonObject("wordlist") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate secrets for mode=crack") }
                    putJsonObject("alg") { put("type", "string"); put("description", "HS256|HS384|HS512 for sign/alg_confusion (default: HS256)") }
                    putJsonObject("payload_overrides") { put("type", "object"); put("description", "Claims to override/add when forging or signing, e.g. {\"sub\":\"admin\"}") }
                },
                required = listOf("token")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val token = args["token"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'token' is required"}""")),
                        isError = true
                    )
                val mode = args["mode"]?.jsonPrimitive?.contentOrNull ?: "analyze"
                val secret = args["secret"]?.jsonPrimitive?.contentOrNull
                val publicKey = args["public_key"]?.jsonPrimitive?.contentOrNull
                val wordlist = args["wordlist"].asStringList()
                val alg = args["alg"]?.jsonPrimitive?.contentOrNull
                val overrides = args["payload_overrides"] as? JsonObject

                val result = bridge.attack(token, mode, secret, publicKey, wordlist, overrides, alg)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())),
                    isError = true
                )
            }
        }
    }
}
