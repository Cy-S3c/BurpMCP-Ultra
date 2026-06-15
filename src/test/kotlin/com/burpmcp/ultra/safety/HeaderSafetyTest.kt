package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HeaderSafetyTest {

    @Test
    fun `containsCrlf detects CR and LF`() {
        assertTrue(HeaderSafety.containsCrlf("a\r\nb"))
        assertTrue(HeaderSafety.containsCrlf("a\nb"))
        assertTrue(HeaderSafety.containsCrlf("a\rb"))
        assertFalse(HeaderSafety.containsCrlf("normal value"))
    }

    @Test
    fun `valid header name and value pass`() {
        assertTrue(HeaderSafety.isValidHeaderName("X-Custom"))
        assertTrue(HeaderSafety.isValidHeaderValue("application/json"))
    }

    @Test
    fun `empty or colon-bearing name is rejected`() {
        assertFalse(HeaderSafety.isValidHeaderName(""))
        assertFalse(HeaderSafety.isValidHeaderName("Bad:Name"))
        assertFalse(HeaderSafety.isValidHeaderName("Bad\r\nName"))
    }

    @Test
    fun `parseHeaderLine splits on the first colon and trims`() {
        val (name, value) = HeaderSafety.parseHeaderLine("X-Test: a: b ")!!
        assertEquals("X-Test", name)
        assertEquals("a: b", value)
    }

    @Test
    fun `parseHeaderLine rejects CRLF injection in the value`() {
        assertNull(HeaderSafety.parseHeaderLine("X-Evil: ok\r\nInjected: 1"))
    }

    @Test
    fun `parseHeaderLine rejects a line with no colon`() {
        assertNull(HeaderSafety.parseHeaderLine("NoColonHere"))
    }
}
