package com.burpmcp.ultra.core

import com.burpmcp.ultra.core.ProxyHistorySearch.Targets
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Guards the proxy_history_search target selection. The original code only honoured
 * "request"/"response"/"both", so an unrecognised value (notably search_in="url")
 * scanned nothing and silently returned 0 matches.
 */
class ProxyHistorySearchTest {

    @Test fun `url scans only the url`() =
        assertEquals(Targets(url = true, request = false, response = false), ProxyHistorySearch.targets("url"))

    @Test fun `request scans only the request`() =
        assertEquals(Targets(url = false, request = true, response = false), ProxyHistorySearch.targets("request"))

    @Test fun `response scans only the response`() =
        assertEquals(Targets(url = false, request = false, response = true), ProxyHistorySearch.targets("response"))

    @Test fun `both scans everything`() =
        assertEquals(Targets(url = true, request = true, response = true), ProxyHistorySearch.targets("both"))

    @Test fun `value is case and whitespace insensitive`() =
        assertEquals(Targets(url = true, request = false, response = false), ProxyHistorySearch.targets("  URL "))

    @Test fun `unknown, null or blank falls back to everything (never silent-zero)`() {
        assertEquals(Targets(url = true, request = true, response = true), ProxyHistorySearch.targets("garbage"))
        assertEquals(Targets(url = true, request = true, response = true), ProxyHistorySearch.targets(null))
        assertEquals(Targets(url = true, request = true, response = true), ProxyHistorySearch.targets(""))
    }
}
