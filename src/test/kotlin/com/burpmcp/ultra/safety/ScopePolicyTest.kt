package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertEquals

class ScopePolicyTest {

    @Test
    fun `OFF always allows`() {
        assertEquals(ScopeDecision.ALLOW, ScopePolicy.decide(ScopeMode.OFF, inScope = false))
        assertEquals(ScopeDecision.ALLOW, ScopePolicy.decide(ScopeMode.OFF, inScope = true))
    }

    @Test
    fun `WARN allows in-scope, warns out-of-scope`() {
        assertEquals(ScopeDecision.ALLOW, ScopePolicy.decide(ScopeMode.WARN, inScope = true))
        assertEquals(ScopeDecision.WARN, ScopePolicy.decide(ScopeMode.WARN, inScope = false))
    }

    @Test
    fun `ENFORCE allows in-scope, denies out-of-scope`() {
        assertEquals(ScopeDecision.ALLOW, ScopePolicy.decide(ScopeMode.ENFORCE, inScope = true))
        assertEquals(ScopeDecision.DENY, ScopePolicy.decide(ScopeMode.ENFORCE, inScope = false))
    }

    @Test
    fun `fromString parses known modes and defaults to WARN`() {
        assertEquals(ScopeMode.OFF, ScopeMode.fromString("off"))
        assertEquals(ScopeMode.ENFORCE, ScopeMode.fromString("ENFORCE"))
        assertEquals(ScopeMode.WARN, ScopeMode.fromString("warn"))
        assertEquals(ScopeMode.WARN, ScopeMode.fromString(null))
        assertEquals(ScopeMode.WARN, ScopeMode.fromString("garbage"))
    }
}
