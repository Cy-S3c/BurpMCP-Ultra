package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PayloadLibrariesTest {

    @Test
    fun `known libraries return non-empty payload sets`() {
        listOf("xss", "sqli", "traversal", "ssti", "cmdi").forEach {
            assertTrue(PayloadLibraries.get(it)!!.isNotEmpty(), "$it should have payloads")
        }
    }

    @Test
    fun `lookup is case-insensitive`() {
        assertEquals(PayloadLibraries.get("xss"), PayloadLibraries.get("XSS"))
    }

    @Test
    fun `unknown library is null`() {
        assertNull(PayloadLibraries.get("definitely-not-a-library"))
    }

    @Test
    fun `representative payloads are present`() {
        assertTrue(PayloadLibraries.get("sqli")!!.any { it.contains("'") })
        assertTrue(PayloadLibraries.get("ssti")!!.contains("{{7*7}}"))
        assertTrue(PayloadLibraries.get("xss")!!.any { it.contains("<script>") })
        assertTrue(PayloadLibraries.get("cmdi")!!.any { it.contains("id") })
    }

    @Test
    fun `names lists the libraries`() {
        assertTrue(PayloadLibraries.names().containsAll(listOf("xss", "sqli", "traversal", "ssti", "cmdi")))
    }
}
