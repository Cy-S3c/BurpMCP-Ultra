package com.burpmcp.ultra.bridge

import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.state.StoredFinding
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant

/**
 * The agent's structured, deduplicated findings memory. Lets an LLM record
 * confirmed/suspected issues once and recall them later for triage and
 * reporting — something the stateless tool surface otherwise lacks. Backed by
 * [StateManager.findings]; no Montoya dependency, so it is unit-testable.
 */
class FindingsBridge(private val stateManager: StateManager) {

    /** Records a finding, or reports it as a duplicate of an existing one (same type+url+location). */
    fun add(type: String, severity: String, url: String, location: String, detail: String, evidence: String): JsonObject {
        val key = dedupKey(type, url, location)
        val existing = stateManager.findings.firstOrNull { dedupKey(it.type, it.url, it.location) == key }
        if (existing != null) {
            return buildJsonObject {
                put("duplicate", true)
                put("id", existing.id)
                put("note", "Matches an existing finding; not added again.")
            }
        }
        val id = stateManager.generateId("finding")
        stateManager.findings.add(StoredFinding(id, type, severity, url, location, detail, evidence, Instant.now().toString()))
        return buildJsonObject {
            put("duplicate", false)
            put("id", id)
            put("total_findings", stateManager.findings.size)
        }
    }

    /** Lists findings, optionally filtered by [severity] and/or [type]. */
    fun list(severity: String?, type: String?): JsonObject {
        val items = stateManager.findings.filter {
            (severity == null || it.severity.equals(severity, true)) &&
                (type == null || it.type.equals(type, true))
        }
        return buildJsonObject {
            put("count", items.size)
            put("findings", buildJsonArray { items.forEach { add(serialize(it)) } })
        }
    }

    private fun serialize(f: StoredFinding): JsonObject = buildJsonObject {
        put("id", f.id)
        put("type", f.type)
        put("severity", f.severity)
        put("url", f.url)
        put("location", f.location)
        put("detail", f.detail)
        put("evidence", f.evidence.take(500))
        put("created_at", f.createdAt)
    }

    companion object {
        /** Dedup identity for a finding: type + url + location, case/space-normalized. */
        fun dedupKey(type: String, url: String, location: String): String =
            "${type.lowercase().trim()}|${url.trim()}|${location.lowercase().trim()}"
    }
}
