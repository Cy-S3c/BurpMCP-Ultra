package com.burpmcp.ultra.bridge

import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class FindingsBridgeTest {

    @Test
    fun `adding the same finding twice is deduplicated`() {
        val b = FindingsBridge(StateManager())
        val r1 = b.add("xss", "high", "http://x/p?q=1", "param:q", "reflected", "<script>")
        assertEquals(false, r1["duplicate"]?.jsonPrimitive?.boolean)
        val r2 = b.add("xss", "high", "http://x/p?q=1", "param:q", "reflected again", "<svg>")
        assertEquals(true, r2["duplicate"]?.jsonPrimitive?.boolean)
        assertEquals(1, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }

    @Test
    fun `a different location is a separate finding`() {
        val b = FindingsBridge(StateManager())
        b.add("xss", "high", "http://x/p", "param:q", "", "")
        b.add("xss", "high", "http://x/p", "param:r", "", "")
        assertEquals(2, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }

    @Test
    fun `list filters by severity and type`() {
        val b = FindingsBridge(StateManager())
        b.add("xss", "high", "http://x/1", "", "", "")
        b.add("info_leak", "low", "http://x/2", "", "", "")
        assertEquals(1, b.list("high", null)["count"]?.jsonPrimitive?.int)
        assertEquals(1, b.list(null, "info_leak")["count"]?.jsonPrimitive?.int)
        assertEquals(2, b.list(null, null)["count"]?.jsonPrimitive?.int)
    }
}
