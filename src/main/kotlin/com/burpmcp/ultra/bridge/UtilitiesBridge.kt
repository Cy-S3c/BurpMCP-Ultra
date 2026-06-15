package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.utilities.CompressionType
import burp.api.montoya.utilities.DigestAlgorithm
import kotlinx.serialization.json.*
import java.security.SecureRandom
import java.util.Base64

class UtilitiesBridge(private val api: MontoyaApi) {

    // ---------------------------------------------------------------
    // URL encoding/decoding
    // ---------------------------------------------------------------

    /**
     * URL-encodes the given data string.
     *
     * @param data The string to encode.
     * @param encodeAll If true, encodes all characters (not just special ones).
     * @return The URL-encoded string.
     */
    fun urlEncode(data: String, encodeAll: Boolean): String {
        return if (encodeAll) {
            com.burpmcp.ultra.core.UrlEncoding.percentEncodeAll(data)
        } else {
            api.utilities().urlUtils().encode(data)
        }
    }

    /**
     * URL-decodes the given data string.
     *
     * @param data The URL-encoded string to decode.
     * @return The decoded string.
     */
    fun urlDecode(data: String): String {
        return api.utilities().urlUtils().decode(data)
    }

    // ---------------------------------------------------------------
    // Base64 encoding/decoding
    // ---------------------------------------------------------------

    /**
     * Base64-encodes the given data string.
     *
     * @param data The string to encode.
     * @param urlSafe If true, uses URL-safe base64 encoding (RFC 4648 Section 5).
     * @return The base64-encoded string.
     */
    fun base64Encode(data: String, urlSafe: Boolean): String {
        val inputBytes = BurpByteArray.byteArray(data)
        return if (urlSafe) {
            // Fall back to Java's URL-safe encoder
            Base64.getUrlEncoder().withoutPadding().encodeToString(data.toByteArray())
        } else {
            api.utilities().base64Utils().encodeToString(inputBytes)
        }
    }

    /**
     * Base64-decodes the given data string.
     *
     * @param data The base64-encoded string to decode.
     * @return The decoded string.
     */
    fun base64Decode(data: String): String {
        return try {
            val decoded = api.utilities().base64Utils().decode(data)
            decoded.toString()
        } catch (e: Exception) {
            // Try URL-safe decoding as fallback
            String(Base64.getUrlDecoder().decode(data))
        }
    }

    // ---------------------------------------------------------------
    // HTML encoding
    // ---------------------------------------------------------------

    /**
     * HTML-encodes the given data string, escaping special characters
     * like <, >, &, ", and '.
     *
     * @param data The string to encode.
     * @return The HTML-encoded string.
     */
    fun htmlEncode(data: String): String {
        return api.utilities().htmlUtils().encode(data)
    }

    // ---------------------------------------------------------------
    // Cryptographic hashing
    // ---------------------------------------------------------------

    /**
     * Computes a cryptographic hash of the given data.
     *
     * @param data The string to hash.
     * @param algorithm One of: MD5, SHA_1, SHA_256, SHA_384, SHA_512.
     * @return JSON object with the hex-encoded hash and algorithm name.
     */
    fun hash(data: String, algorithm: String): JsonObject {
        val digestAlgorithm = when (algorithm.uppercase().replace("-", "_")) {
            "MD5" -> DigestAlgorithm.MD5
            "SHA1", "SHA_1" -> DigestAlgorithm.SHA_1
            "SHA256", "SHA_256" -> DigestAlgorithm.SHA_256
            "SHA384", "SHA_384" -> DigestAlgorithm.SHA_384
            "SHA512", "SHA_512" -> DigestAlgorithm.SHA_512
            else -> throw IllegalArgumentException(
                "Unsupported hash algorithm: '$algorithm'. " +
                    "Supported: MD5, SHA_1, SHA_256, SHA_384, SHA_512"
            )
        }

        val inputBytes = BurpByteArray.byteArray(data)
        val hashBytes = api.utilities().cryptoUtils().generateDigest(inputBytes, digestAlgorithm)
        val hexHash = hashBytes.bytes.joinToString("") { "%02x".format(it) }

        return buildJsonObject {
            put("algorithm", digestAlgorithm.name)
            put("hash", hexHash)
            put("input_length", data.length)
        }
    }

    // ---------------------------------------------------------------
    // Compression
    // ---------------------------------------------------------------

    /**
     * Compresses data using the specified algorithm.
     *
     * @param data Base64-encoded input data.
     * @param algorithm One of: GZIP, DEFLATE, BROTLI.
     * @return JSON object with the base64-encoded compressed data.
     */
    fun compress(data: String, algorithm: String): JsonObject {
        val compressionType = resolveCompressionType(algorithm)
        val decodedBytes = Base64.getDecoder().decode(data)
        val inputBytes = BurpByteArray.byteArray(*decodedBytes)
        val compressed = api.utilities().compressionUtils().compress(inputBytes, compressionType)
        val encodedResult = Base64.getEncoder().encodeToString(compressed.getBytes())

        return buildJsonObject {
            put("algorithm", compressionType.name)
            put("compressed", encodedResult)
            put("original_size", inputBytes.length())
            put("compressed_size", compressed.length())
            put("ratio", if (inputBytes.length() > 0) {
                "%.2f".format(compressed.length().toDouble() / inputBytes.length().toDouble())
            } else {
                "0.00"
            })
        }
    }

    /**
     * Decompresses data using the specified algorithm.
     *
     * @param data Base64-encoded compressed data.
     * @param algorithm One of: GZIP, DEFLATE, BROTLI.
     * @return JSON object with the base64-encoded decompressed data.
     */
    fun decompress(data: String, algorithm: String): JsonObject {
        val compressionType = resolveCompressionType(algorithm)
        val decodedBytes = Base64.getDecoder().decode(data)
        val inputBytes = BurpByteArray.byteArray(*decodedBytes)
        val decompressed = api.utilities().compressionUtils().decompress(inputBytes, compressionType)
        val encodedResult = Base64.getEncoder().encodeToString(decompressed.getBytes())

        return buildJsonObject {
            put("algorithm", compressionType.name)
            put("decompressed", encodedResult)
            put("compressed_size", inputBytes.length())
            put("decompressed_size", decompressed.length())
            // Try to include the decompressed string if it's valid UTF-8
            try {
                val text = String(decompressed.getBytes(), Charsets.UTF_8)
                put("decompressed_text", text)
            } catch (_: Exception) {
                // Binary content; base64 only
            }
        }
    }

    private fun resolveCompressionType(algorithm: String): CompressionType {
        return when (algorithm.uppercase()) {
            "GZIP" -> CompressionType.GZIP
            "DEFLATE" -> CompressionType.DEFLATE
            "BROTLI" -> CompressionType.BROTLI
            else -> throw IllegalArgumentException(
                "Unsupported compression algorithm: '$algorithm'. " +
                    "Supported: GZIP, DEFLATE, BROTLI"
            )
        }
    }

    // ---------------------------------------------------------------
    // Random generation
    // ---------------------------------------------------------------

    /**
     * Generates a random string of the specified length using the given
     * character set.
     *
     * @param length The desired string length.
     * @param charset The character set to draw from. Accepts predefined names
     *                ("alphanumeric", "alpha", "numeric", "hex", "ascii") or
     *                a custom string of characters.
     * @return JSON object with the generated random string.
     */
    fun randomString(length: Int, charset: String): JsonObject {
        val chars = when (charset.lowercase()) {
            "alphanumeric" -> "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            "alpha" -> "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "numeric" -> "0123456789"
            "hex" -> "0123456789abcdef"
            "ascii" -> (32..126).map { it.toChar() }.joinToString("")
            else -> charset // Use the provided string as-is
        }

        if (chars.isEmpty()) {
            throw IllegalArgumentException("Character set cannot be empty")
        }

        val random = SecureRandom()
        val result = StringBuilder(length)
        for (i in 0 until length) {
            result.append(chars[random.nextInt(chars.length)])
        }

        return buildJsonObject {
            put("value", result.toString())
            put("length", length)
            put("charset", charset)
        }
    }

    /**
     * Generates cryptographically random bytes.
     *
     * @param length The number of random bytes to generate.
     * @return JSON object with hex-encoded and base64-encoded representations.
     */
    fun randomBytes(length: Int): JsonObject {
        val random = SecureRandom()
        val bytes = ByteArray(length)
        random.nextBytes(bytes)

        val hex = bytes.joinToString("") { "%02x".format(it) }
        val base64 = Base64.getEncoder().encodeToString(bytes)

        return buildJsonObject {
            put("hex", hex)
            put("base64", base64)
            put("length", length)
        }
    }

    // ---------------------------------------------------------------
    // JWT decoding
    // ---------------------------------------------------------------

    /**
     * Decodes a JSON Web Token (JWT) without signature verification by default.
     *
     * Splits the token on '.', base64-decodes the header and payload,
     * and parses them as JSON. Checks the exp claim for expiration.
     *
     * @param token The JWT string.
     * @param verifySignature If true, attempt to verify the signature (requires secret).
     * @param secret The secret/key for HMAC signature verification.
     * @return JSON object with decoded header, payload, signature info, and expiration status.
     */
    fun jwtDecode(token: String, verifySignature: Boolean, secret: String?): JsonObject {
        val parts = token.split(".")
        if (parts.size != 3) {
            throw IllegalArgumentException(
                "Invalid JWT format: expected 3 parts separated by '.', got ${parts.size}"
            )
        }

        val headerJson = decodeJwtPart(parts[0])
        val payloadJson = decodeJwtPart(parts[1])
        val signatureBase64 = parts[2]

        // Parse header and payload as JSON
        val header = try {
            Json.parseToJsonElement(headerJson).jsonObject
        } catch (e: Exception) {
            buildJsonObject { put("raw", headerJson) }
        }

        val payload = try {
            Json.parseToJsonElement(payloadJson).jsonObject
        } catch (e: Exception) {
            buildJsonObject { put("raw", payloadJson) }
        }

        // Check expiration
        val exp = payload["exp"]?.jsonPrimitive?.longOrNull
        val now = System.currentTimeMillis() / 1000
        val isExpired = if (exp != null) exp < now else null

        return buildJsonObject {
            put("header", header)
            put("payload", payload)
            put("signature", signatureBase64)

            if (exp != null) {
                put("expires_at", exp)
                put("is_expired", isExpired!!)
                if (isExpired) {
                    put("expired_ago_seconds", now - exp)
                } else {
                    put("expires_in_seconds", exp - now)
                }
            }

            val iat = payload["iat"]?.jsonPrimitive?.longOrNull
            if (iat != null) {
                put("issued_at", iat)
            }

            val nbf = payload["nbf"]?.jsonPrimitive?.longOrNull
            if (nbf != null) {
                put("not_before", nbf)
            }

            if (verifySignature) {
                if (secret.isNullOrEmpty()) {
                    put("signature_verified", false)
                    put("signature_error", "No secret provided for verification")
                } else {
                    try {
                        val alg = header["alg"]?.jsonPrimitive?.content ?: "unknown"
                        val hmacAlgorithm = when (alg.uppercase()) {
                            "HS256" -> "HmacSHA256"
                            "HS384" -> "HmacSHA384"
                            "HS512" -> "HmacSHA512"
                            else -> null
                        }

                        if (hmacAlgorithm != null) {
                            val mac = javax.crypto.Mac.getInstance(hmacAlgorithm)
                            val secretKey = javax.crypto.spec.SecretKeySpec(
                                secret.toByteArray(), hmacAlgorithm
                            )
                            mac.init(secretKey)
                            val sigInput = "${parts[0]}.${parts[1]}"
                            val computed = mac.doFinal(sigInput.toByteArray())
                            val computedBase64 = Base64.getUrlEncoder()
                                .withoutPadding()
                                .encodeToString(computed)
                            val verified = computedBase64 == signatureBase64
                            put("signature_verified", verified)
                            put("signature_algorithm", alg)
                        } else {
                            put("signature_verified", false)
                            put("signature_error",
                                "Unsupported algorithm for verification: $alg. " +
                                    "Only HS256/HS384/HS512 are supported."
                            )
                        }
                    } catch (e: Exception) {
                        put("signature_verified", false)
                        put("signature_error", "Verification failed: ${e.message}")
                    }
                }
            } else {
                put("signature_verified", false)
                put("signature_note", "Signature verification not requested")
            }
        }
    }

    /**
     * Decodes a single base64url-encoded JWT part to a UTF-8 string.
     */
    private fun decodeJwtPart(part: String): String {
        // JWT uses base64url encoding (no padding)
        val padded = when (part.length % 4) {
            2 -> "$part=="
            3 -> "$part="
            else -> part
        }
        val bytes = Base64.getUrlDecoder().decode(padded)
        return String(bytes, Charsets.UTF_8)
    }

    // ---------------------------------------------------------------
    // Smart decoding
    // ---------------------------------------------------------------

    /**
     * Iteratively attempts to decode the given data through multiple encoding
     * layers (base64, URL encoding, hex) up to [maxDepth] levels.
     *
     * @param data The encoded data string.
     * @param maxDepth Maximum number of decoding iterations.
     * @return JSON object with original value, final decoded value, and
     *         an array of decoding steps taken.
     */
    fun decodeSmart(data: String, maxDepth: Int): JsonObject {
        val steps = mutableListOf<JsonObject>()
        var current = data
        var depth = 0

        while (depth < maxDepth) {
            var changed = false

            // 1. Try base64 decode
            if (!changed) {
                try {
                    // Check if it looks like base64 (length divisible by 4 or padded,
                    // and contains only valid chars)
                    val cleaned = current.trim()
                    if (cleaned.length >= 4 && cleaned.matches(Regex("^[A-Za-z0-9+/=\\-_]+$"))) {
                        val decoded = try {
                            String(Base64.getDecoder().decode(cleaned), Charsets.UTF_8)
                        } catch (_: Exception) {
                            // Try URL-safe base64
                            String(Base64.getUrlDecoder().decode(cleaned), Charsets.UTF_8)
                        }
                        // Check if the result is valid UTF-8 and different from input
                        if (decoded != current && decoded.all { it.code < 0xFFFD && !it.isISOControl() || it == '\n' || it == '\r' || it == '\t' }) {
                            steps.add(buildJsonObject {
                                put("step", depth + 1)
                                put("encoding", "base64")
                                put("input", current)
                                put("output", decoded)
                            })
                            current = decoded
                            changed = true
                        }
                    }
                } catch (_: Exception) {
                    // Not valid base64
                }
            }

            // 2. Try URL decode
            if (!changed) {
                try {
                    if (current.contains('%')) {
                        val decoded = java.net.URLDecoder.decode(current, "UTF-8")
                        if (decoded != current) {
                            steps.add(buildJsonObject {
                                put("step", depth + 1)
                                put("encoding", "url")
                                put("input", current)
                                put("output", decoded)
                            })
                            current = decoded
                            changed = true
                        }
                    }
                } catch (_: Exception) {
                    // Not valid URL encoding
                }
            }

            // 3. Try hex decode
            if (!changed) {
                try {
                    val trimmed = current.trim()
                    if (trimmed.length >= 2 &&
                        trimmed.length % 2 == 0 &&
                        trimmed.matches(Regex("^[0-9a-fA-F]+$"))
                    ) {
                        val decoded = trimmed.chunked(2)
                            .map { it.toInt(16).toByte() }
                            .toByteArray()
                        val decodedStr = String(decoded, Charsets.UTF_8)
                        if (decodedStr != current && decodedStr.all { it.code < 0xFFFD && !it.isISOControl() || it == '\n' || it == '\r' || it == '\t' }) {
                            steps.add(buildJsonObject {
                                put("step", depth + 1)
                                put("encoding", "hex")
                                put("input", current)
                                put("output", decodedStr)
                            })
                            current = decodedStr
                            changed = true
                        }
                    }
                } catch (_: Exception) {
                    // Not valid hex
                }
            }

            // If no decoding step produced a change, stop
            if (!changed) break

            depth++
        }

        return buildJsonObject {
            put("original", data)
            put("decoded", current)
            put("layers", depth)
            putJsonArray("steps") {
                steps.forEach { add(it) }
            }
            put("fully_decoded", depth == 0 || current == data)
        }
    }

    // Shell execution (shellExecute / util_shell_execute) was removed in 2.0.6.
    // It was a raw ProcessBuilder mis-documented as "Burp's safe shell API" and,
    // with the previously unauthenticated transports, an RCE primitive reachable
    // from any website the operator visited. Do not reintroduce it.
}
