package com.burpmcp.ultra.webprobe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class CorsAnalysisTest {

    @Test
    fun `reflected origin with credentials is critical`() {
        val v = CorsAnalysis.assess("https://evil.example", "https://evil.example", "true")
        assertEquals("critical", v?.severity)
        assertEquals("reflected_origin_with_creds", v?.id)
    }

    @Test
    fun `reflected origin without credentials is high`() {
        val v = CorsAnalysis.assess("https://evil.example", "https://evil.example", null)
        assertEquals("high", v?.severity)
        assertEquals("reflected_origin", v?.id)
    }

    @Test
    fun `null origin allowed is high`() {
        val v = CorsAnalysis.assess("null", "null", "true")
        assertEquals("high", v?.severity)
        assertEquals("null_origin_allowed", v?.id)
    }

    @Test
    fun `wildcard without credentials is low`() {
        assertEquals("low", CorsAnalysis.assess("https://evil.example", "*", null)?.severity)
    }

    @Test
    fun `non-reflected site-specific ACAO is not a finding`() {
        assertNull(CorsAnalysis.assess("https://evil.example", "https://trusted.example", "true"))
    }

    @Test
    fun `absent ACAO is not a finding`() {
        assertNull(CorsAnalysis.assess("https://evil.example", null, null))
    }
}
