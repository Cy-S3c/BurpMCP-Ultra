package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class AuthDiffVerdictTest {

    // exact-match similarity for deterministic tests (0 or 100)
    private val sim = { a: String, b: String -> if (a == b) 100.0 else 0.0 }
    private fun lr(name: String, status: Int, body: String) = AuthDiffVerdict.LevelResult(name, status, body)

    @Test
    fun `flags all-identical responses as critical broken access control`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "data"), lr("user", 200, "data"), lr("none", 200, "data")), sim)
        assertTrue(f.any { it.id == "all_identical" && it.severity == "critical" })
    }

    @Test
    fun `flags an unauth level that returns the same protected body as an authed level`() {
        val f = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, "secret"), lr("user", 403, "denied"), lr("none", 200, "secret")), sim
        )
        assertTrue(f.any { it.id == "unauth_reads_protected" && it.severity == "critical" })
    }

    @Test
    fun `flags an unauth-accessible endpoint even when the body differs`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 200, "public-page")), sim)
        assertTrue(f.any { it.id == "unauth_accessible" && it.severity == "high" })
        assertFalse(f.any { it.id == "unauth_reads_protected" })
    }

    @Test
    fun `proper enforcement (authed 200, unauth 401) yields no critical or high finding`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 401, "denied")), sim)
        assertFalse(f.any { it.severity == "critical" || it.severity == "high" })
    }
}
