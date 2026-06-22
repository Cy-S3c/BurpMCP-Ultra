package com.burpmcp.ultra.jwt

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwtTest {

    // Canonical jwt.io HS256 example. Signed with the secret "your-256-bit-secret".
    private val token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    @Test
    fun `decode extracts alg and claims`() {
        val p = Jwt.decode(token)!!
        assertEquals("HS256", p.alg)
        assertEquals("1234567890", p.payload["sub"]?.jsonPrimitive?.content)
    }

    @Test
    fun `base64url round-trips without padding`() {
        val s = "any string with ünïcode + symbols/?"
        assertEquals(s, String(Jwt.b64UrlDecode(Jwt.b64UrlEncode(s)), Charsets.UTF_8))
    }

    @Test
    fun `crack finds the HMAC secret against the known jwt-io vector`() {
        assertEquals("your-256-bit-secret", Jwt.crack(token, listOf("nope", "your-256-bit-secret", "x")))
    }

    @Test
    fun `crack returns null when the secret is not in the list`() {
        assertNull(Jwt.crack(token, listOf("a", "b", "c")))
    }

    @Test
    fun `crack tolerates an empty candidate and still finds the secret`() {
        // An empty key makes JCA's SecretKeySpec throw "Empty key"; crack must skip
        // it (and any bad candidate) instead of aborting the whole wordlist.
        assertEquals("your-256-bit-secret", Jwt.crack(token, listOf("", "wrong", "your-256-bit-secret")))
    }

    @Test
    fun `forgeNone produces alg-none variants with an empty signature`() {
        val forged = Jwt.forgeNone(token)
        assertTrue(forged.size >= 3)
        forged.forEach { t ->
            assertTrue(t.endsWith("."), "alg:none token must have an empty signature")
            assertTrue(Jwt.decode(t)!!.alg!!.equals("none", ignoreCase = true))
        }
    }

    @Test
    fun `resign produces a token verifiable with the new key and applies overrides`() {
        val forged = Jwt.resign(token, "newsecret", "HS256", buildJsonObject { put("sub", "admin") })!!
        val p = Jwt.decode(forged)!!
        assertEquals("admin", p.payload["sub"]?.jsonPrimitive?.content)
        assertEquals("newsecret", Jwt.crack(forged, listOf("newsecret")))
    }

    @Test
    fun `analyze flags alg none and missing exp`() {
        val none = Jwt.forgeNone(token).first()
        val ids = Jwt.analyze(none).map { it.id }
        assertTrue("alg_none" in ids)
        assertTrue("no_exp" in ids)
    }

    @Test
    fun `analyze flags an HMAC alg as crackable`() {
        assertTrue("alg_hmac" in Jwt.analyze(token).map { it.id })
    }
}
