package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Issue #20: proxy_history / proxy_history_search used to serialize request header values
 * unconditionally — a live Cookie/Authorization entered the LLM's context on a recon query.
 * Names keep their shape; sensitive VALUES are masked unless include_request=true.
 */
class SensitiveHeadersTest {

    @Test fun `credential headers are recognized case- and whitespace-insensitively`() {
        assertTrue(SensitiveHeaders.isSensitive("Authorization"))
        assertTrue(SensitiveHeaders.isSensitive("authorization"))
        assertTrue(SensitiveHeaders.isSensitive("  COOKIE "))
        assertTrue(SensitiveHeaders.isSensitive("Set-Cookie"))
        assertTrue(SensitiveHeaders.isSensitive("X-API-Key"))
        assertTrue(SensitiveHeaders.isSensitive("X-Auth-Token"))
        assertTrue(SensitiveHeaders.isSensitive("Proxy-Authorization"))
    }

    @Test fun `non-credential headers pass through`() {
        assertFalse(SensitiveHeaders.isSensitive("User-Agent"))
        assertFalse(SensitiveHeaders.isSensitive("Content-Type"))
        assertFalse(SensitiveHeaders.isSensitive("Referer"))
        assertFalse(SensitiveHeaders.isSensitive("X-Custom-Header"))
        assertFalse(SensitiveHeaders.isSensitive(""))
    }

    @Test fun `values are redacted by default and revealed with include_request`() {
        assertEquals(SensitiveHeaders.REDACTED, SensitiveHeaders.value("Cookie", "session=abc", reveal = false))
        assertEquals("session=abc", SensitiveHeaders.value("Cookie", "session=abc", reveal = true))
        assertEquals("Mozilla/5.0", SensitiveHeaders.value("User-Agent", "Mozilla/5.0", reveal = false))
    }
}
