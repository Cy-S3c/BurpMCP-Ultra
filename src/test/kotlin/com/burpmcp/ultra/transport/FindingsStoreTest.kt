package com.burpmcp.ultra.transport

import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.state.StoredFinding
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FindingsStoreTest {

    private fun finding(
        id: String = "finding-001",
        type: String = "idor",
        severity: String = "high",
        url: String = "https://x.com/api/users/2"
    ) = StoredFinding(id, type, severity, url, "param:id", "cross-user read", "owner canary reflected", "2026-09-15T10:00:00Z")

    @Test fun `round-trips a finding with its project tag`() {
        val (back, proj) = FindingsStore.parseEntry(FindingsStore.buildEntry(finding(id = "finding-007", type = "cors"), "ProjA"))!!
        assertEquals("finding-007", back.id)
        assertEquals("cors", back.type)
        assertEquals("high", back.severity)
        assertEquals("https://x.com/api/users/2", back.url)
        assertEquals("param:id", back.location)
        assertEquals("cross-user read", back.detail)
        assertEquals("owner canary reflected", back.evidence)
        assertEquals("2026-09-15T10:00:00Z", back.createdAt)
        assertEquals("ProjA", proj)
    }

    @Test fun `parseEntry tolerates malformed lines`() {
        assertNull(FindingsStore.parseEntry("not json {"))
        assertNull(FindingsStore.parseEntry(""))
    }

    @Test fun `rebuildLines deletes a project keeping others`() {
        val parsed = listOf(finding("finding-001") to "A", finding("finding-002") to "B", finding("finding-003") to "A")
        val back = FindingsStore.rebuildLines(parsed, "A", emptyList()).mapNotNull { FindingsStore.parseEntry(it) }
        assertEquals(listOf("finding-002"), back.map { it.first.id }, "only project B should remain")
        assertTrue(back.all { it.second == "B" })
    }

    @Test fun `rebuildLines replaces a project's entries and keeps others`() {
        val parsed = listOf(finding("finding-001") to "A", finding("finding-002") to "B")
        val back = FindingsStore.rebuildLines(parsed, "A", listOf(finding("finding-009"), finding("finding-010")))
            .mapNotNull { FindingsStore.parseEntry(it) }
        assertEquals(listOf("finding-002", "finding-009", "finding-010"), back.map { it.first.id })
        assertEquals("A", back.first { it.first.id == "finding-009" }.second)
    }

    // --- restore semantics: the id counter must continue past restored suffixes ---

    @Test fun `restoreFindings seeds the list and continues the id sequence`() {
        val sm = StateManager()
        sm.restoreFindings(listOf(finding("finding-041"), finding("finding-007")))
        assertEquals(2, sm.findings.size)
        // The next generated id must clear the highest restored numeric suffix (41)…
        assertEquals("finding-042", sm.generateId("finding"))
        // …and stays globally unique across prefixes (shared counter).
        assertTrue(sm.generateId("prule").endsWith("043"))
    }

    @Test fun `restoreFindings on empty list is a no-op`() {
        val sm = StateManager()
        sm.restoreFindings(emptyList())
        assertTrue(sm.findings.isEmpty())
        assertEquals("prule-001", sm.generateId("prule"))
    }

    @Test fun `restoreFindings ignores non-numeric suffixes without throwing`() {
        val sm = StateManager()
        sm.restoreFindings(listOf(finding(id = "weird")))
        assertEquals(1, sm.findings.size)
        assertEquals("finding-001", sm.generateId("finding"))
    }

    @Test fun `addFinding notifies listeners but restoreFindings does not`() {
        val sm = StateManager()
        val seen = mutableListOf<StoredFinding>()
        sm.findingsListeners.add { seen.add(it) }
        sm.restoreFindings(listOf(finding("finding-001")))
        assertTrue(seen.isEmpty(), "restore must not notify persistence listeners (would duplicate on disk)")
        sm.addFinding(finding("finding-002"))
        assertEquals(listOf("finding-002"), seen.map { it.id })
        assertEquals(2, sm.findings.size)
    }

    // --- extended fields (CVSS / OWASP / steps / request / response) ---

    @Test fun `round-trips the extended finding fields`() {
        val full = StoredFinding(
            "finding-005", "idor", "critical", "https://x.com/api/users/2", "param:id",
            "cross-user read", "canary", "2026-09-15T10:00:00Z",
            cvssScore = "8.1", cvssVector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            owaspCategory = "A01:2021 - Broken Access Control",
            stepsToReproduce = "1. login as user A\n2. GET /api/users/2",
            request = "GET /api/users/2 HTTP/1.1\r\nHost: x.com\r\n\r\n",
            response = "HTTP/1.1 200 OK\r\n\r\n{\"email\":\"user2@x.com\"}"
        )
        val (back, proj) = FindingsStore.parseEntry(FindingsStore.buildEntry(full, "ProjA"))!!
        assertEquals(full, back)
        assertEquals("ProjA", proj)
    }

    @Test fun `records written before the extended fields parse with defaults`() {
        val legacy =
            """{"id":"finding-001","type":"xss","severity":"high","url":"http://x/p","location":"param:q",""" +
                """"detail":"reflected","evidence":"<script>","created_at":"2026-09-15T10:00:00Z","project":"P"}"""
        val (f, proj) = FindingsStore.parseEntry(legacy)!!
        assertEquals("finding-001", f.id)
        assertEquals("", f.cvssScore)
        assertEquals("", f.cvssVector)
        assertEquals("", f.owaspCategory)
        assertEquals("", f.stepsToReproduce)
        assertEquals("", f.request)
        assertEquals("", f.response)
        assertEquals("P", proj)
    }
}
