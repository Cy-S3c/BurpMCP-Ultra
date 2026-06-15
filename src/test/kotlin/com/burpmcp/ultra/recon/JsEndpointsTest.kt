package com.burpmcp.ultra.recon

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsEndpointsTest {

    @Test
    fun `extracts quoted absolute paths`() {
        val out = JsEndpoints.extract("""fetch("/api/v1/users").then(r=>r.json())""")
        assertTrue("/api/v1/users" in out)
    }

    @Test
    fun `extracts paths with query strings and full urls`() {
        val out = JsEndpoints.extract("""axios.get('/admin/settings?tab=1'); var b='https://api.example.com/v2/data';""")
        assertTrue("/admin/settings?tab=1" in out)
        assertTrue("https://api.example.com/v2/data" in out)
    }

    @Test
    fun `ignores a bare slash and protocol-relative noise`() {
        val out = JsEndpoints.extract("""var a="/"; var b="//cdn.example.com/lib.js";""")
        assertFalse("/" in out)
    }

    @Test
    fun `deduplicates repeated endpoints`() {
        val out = JsEndpoints.extract("""call("/api/x"); again("/api/x");""")
        assertTrue(out.count { it == "/api/x" } == 1)
    }
}
