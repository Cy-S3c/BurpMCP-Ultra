package com.burpmcp.ultra.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class InjectionOracleTest {

    @Test
    fun `detects SQL error signatures by dbms`() {
        assertEquals("mysql", InjectionOracle.sqlError("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
        assertEquals("oracle", InjectionOracle.sqlError("ORA-00933: SQL command not properly ended"))
        assertEquals("postgresql", InjectionOracle.sqlError("PostgreSQL query failed: ERROR: unterminated quoted string"))
        assertNull(InjectionOracle.sqlError("a perfectly normal response body"))
    }

    @Test
    fun `evaluatedTo detects template math evaluation`() {
        assertTrue(InjectionOracle.evaluatedTo("the answer is 1787569 today", "1787569"))
        assertFalse(InjectionOracle.evaluatedTo("the answer is {{1337*1337}} today", "1787569"))
    }

    @Test
    fun `fileMarker detects etc-passwd and win-ini`() {
        assertEquals("unix-passwd", InjectionOracle.fileMarker("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
        assertEquals("windows-ini", InjectionOracle.fileMarker("; for 16-bit app support\r\n[fonts]\r\n[extensions]"))
        assertNull(InjectionOracle.fileMarker("hello world, nothing to see"))
    }

    @Test
    fun `timeDelayed flags a clear delay and ignores a fast response`() {
        assertTrue(InjectionOracle.timeDelayed(baselineMs = 120, probeMs = 5300, expectedDelaySec = 5))
        assertFalse(InjectionOracle.timeDelayed(baselineMs = 120, probeMs = 350, expectedDelaySec = 5))
    }
}
