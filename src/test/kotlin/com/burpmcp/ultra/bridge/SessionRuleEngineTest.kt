package com.burpmcp.ultra.bridge

import com.burpmcp.ultra.state.SessionRule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionRuleEngineTest {

    private fun rule(
        scope: String = "all",
        scopePattern: String? = null,
        extractFrom: String = "body",
        extractHeaderName: String? = null,
        extractRegex: String = "token=(\\w+)",
        injectInto: String = "header",
        injectName: String = "X-Token",
        injectValueTemplate: String = "Bearer {value}"
    ) = SessionRule(
        ruleName = "r", scope = scope, scopePattern = scopePattern,
        extractFrom = extractFrom, extractHeaderName = extractHeaderName, extractRegex = extractRegex,
        injectInto = injectInto, injectName = injectName, injectValueTemplate = injectValueTemplate
    )

    @Test
    fun `extracts the capture group from a body`() {
        assertEquals("abc123", SessionRuleEngine.extract(rule(extractFrom = "body", extractRegex = "token=(\\w+)"), null, "x token=abc123 y"))
    }

    @Test
    fun `extracts from a header value`() {
        val r = rule(extractFrom = "header", extractHeaderName = "Set-Cookie", extractRegex = "SESSION=([^;]+)")
        assertEquals("xyz", SessionRuleEngine.extract(r, "SESSION=xyz; Path=/; HttpOnly", ""))
    }

    @Test
    fun `falls back to the whole match when there is no capture group`() {
        assertEquals("v=1", SessionRuleEngine.extract(rule(extractRegex = "v=\\d"), null, "a v=1 b"))
    }

    @Test
    fun `returns null when nothing matches or header is absent`() {
        assertNull(SessionRuleEngine.extract(rule(extractRegex = "zzz=(\\d+)"), null, "nothing here"))
        assertNull(SessionRuleEngine.extract(rule(extractFrom = "header", extractHeaderName = "X"), null, "body"))
    }

    @Test
    fun `inScope handles all, custom, and suite`() {
        assertTrue(SessionRuleEngine.inScope(rule(scope = "all"), "http://x/", suiteInScope = false))
        assertTrue(SessionRuleEngine.inScope(rule(scope = "custom", scopePattern = "example\\.com"), "http://example.com/a", false))
        assertFalse(SessionRuleEngine.inScope(rule(scope = "custom", scopePattern = "example\\.com"), "http://other.com/", false))
        assertTrue(SessionRuleEngine.inScope(rule(scope = "suite"), "http://x/", suiteInScope = true))
        assertFalse(SessionRuleEngine.inScope(rule(scope = "suite"), "http://x/", suiteInScope = false))
    }

    @Test
    fun `render substitutes the value placeholder`() {
        assertEquals("Bearer abc", SessionRuleEngine.render("Bearer {value}", "abc"))
    }
}
