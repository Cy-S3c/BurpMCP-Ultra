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

    /**
     * Records a finding, or reports it as a duplicate of an existing one (same type+url+location).
     * [cvssScore] must be blank or a number 0.0–10.0; [owaspCategory] is normalized to its
     * canonical OWASP Top 10 2021 form when recognized (see [Owasp2021]).
     */
    fun add(
        type: String,
        severity: String,
        url: String,
        location: String,
        detail: String,
        evidence: String,
        cvssScore: String = "",
        cvssVector: String = "",
        owaspCategory: String = "",
        stepsToReproduce: String = "",
        request: String = "",
        response: String = ""
    ): JsonObject {
        val score = cvssScore.trim()
        if (score.isNotEmpty()) {
            val v = score.toDoubleOrNull()
            if (v == null || v < 0.0 || v > 10.0) {
                return buildJsonObject {
                    put("error", "Invalid cvss_score '$cvssScore': must be a number between 0.0 and 10.0 (e.g. 8.1)")
                }
            }
        }
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
        val finding = StoredFinding(
            id, type, severity, url, location, detail, evidence, Instant.now().toString(),
            cvssScore = score,
            cvssVector = cvssVector.trim(),
            owaspCategory = Owasp2021.normalize(owaspCategory),
            stepsToReproduce = stepsToReproduce.trim(),
            request = request,
            response = response
        )
        stateManager.addFinding(finding)
        return buildJsonObject {
            put("duplicate", false)
            put("id", id)
            put("owasp_category", finding.owaspCategory)
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
        put("cvss_score", f.cvssScore)
        put("cvss_vector", f.cvssVector)
        put("owasp_category", f.owaspCategory)
        put("steps_to_reproduce", f.stepsToReproduce)
        put("request", f.request.take(4000))
        put("response", f.response.take(4000))
        put("created_at", f.createdAt)
    }

    companion object {
        /** Dedup identity for a finding: type + url + location, case/space-normalized. */
        fun dedupKey(type: String, url: String, location: String): String =
            "${type.lowercase().trim()}|${url.trim()}|${location.lowercase().trim()}"
    }
}

/**
 * OWASP Top 10 (2021) category normalizer. Accepts a code ("A03", "a03:2021"),
 * a category name ("Injection", "broken access control", "SSRF"), or a full
 * canonical string, and maps it to the canonical "Axx:2021 - Name" form.
 * Unrecognized input is passed through unchanged so a novel category still
 * records something actionable. Pure; unit-tested.
 */
object Owasp2021 {
    /** Canonical entries, code order — also the valid-values list surfaced in the tool schema. */
    val categories: List<String> = listOf(
        "A01:2021 - Broken Access Control",
        "A02:2021 - Cryptographic Failures",
        "A03:2021 - Injection",
        "A04:2021 - Insecure Design",
        "A05:2021 - Security Misconfiguration",
        "A06:2021 - Vulnerable and Outdated Components",
        "A07:2021 - Identification and Authentication Failures",
        "A08:2021 - Software and Data Integrity Failures",
        "A09:2021 - Security Logging and Monitoring Failures",
        "A10:2021 - Server-Side Request Forgery (SSRF)"
    )

    private val byCode = categories.associateBy { it.substringBefore(':') }

    private val byName: Map<String, String> = buildMap {
        for (e in categories) {
            val name = e.substringAfter(" - ")
            put(key(name), e)
            // Also register the name without a parenthetical, e.g. "Server-Side Request Forgery"
            put(key(name.substringBefore(" (")), e)
        }
    }

    // Common shorthands that don't collide with full names.
    private val aliases = mapOf(
        key("SSRF") to categories.last()
    )

    /** Case/punctuation-insensitive comparison key. */
    private fun key(s: String) = s.lowercase().filter { it.isLetterOrDigit() }

    fun normalize(input: String): String {
        val t = input.trim()
        if (t.isEmpty()) return ""
        val codePart = t.uppercase().substringBefore(':').substringBefore('-').trim()
        byCode[codePart]?.let { return it }
        val k = key(t)
        byName[k]?.let { return it }
        aliases[k]?.let { return it }
        return t
    }

    /** Comma-joined canonical list for tool descriptions / error messages. */
    fun validValues(): String = categories.joinToString(", ")
}
