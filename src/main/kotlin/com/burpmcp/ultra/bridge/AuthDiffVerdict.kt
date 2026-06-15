package com.burpmcp.ultra.bridge

/**
 * Pure broken-access-control verdict for auth-diff results. Improves on the old
 * inline check (which only flagged an exact `status == 200` match) by reasoning
 * across the 2xx/3xx range and using body similarity, so it catches an
 * unauthenticated/lower-privilege identity that can read a protected resource.
 */
object AuthDiffVerdict {

    data class LevelResult(val name: String, val status: Int, val body: String) {
        /** Levels named none/unauth/anonymous are treated as the lower-privilege baseline. */
        val isAuthLevel: Boolean
            get() = !name.equals("none", true) && !name.equals("unauth", true) && !name.equals("anonymous", true)
        val isSuccess: Boolean get() = status in 200..399
    }

    data class Finding(val severity: String, val id: String, val detail: String)

    /**
     * @param similarity returns 0..100 body similarity (the bridge supplies its
     *   bigram-Dice metric; tests supply an exact-match stub).
     */
    fun assess(results: List<LevelResult>, similarity: (String, String) -> Double): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (results.size < 2) return findings

        val statuses = results.map { it.status }.distinct()
        val allSameStatus = statuses.size == 1
        val firstBody = results.first().body
        val allSimilar = results.all { similarity(firstBody, it.body) >= 95.0 }

        // Dominant case: every level gets the same status + near-identical body.
        if (allSameStatus && allSimilar) {
            findings.add(
                Finding(
                    "critical", "all_identical",
                    "All auth levels return the same status and near-identical bodies — likely missing authorization checks."
                )
            )
            return findings
        }

        val authLevels = results.filter { it.isAuthLevel }
        val unauthLevels = results.filter { !it.isAuthLevel }

        for (u in unauthLevels) {
            if (!u.isSuccess) continue
            val match = authLevels.firstOrNull { a -> a.isSuccess && similarity(a.body, u.body) >= 90.0 }
            if (match != null) {
                findings.add(
                    Finding(
                        "critical", "unauth_reads_protected",
                        "'${u.name}' returns ${u.status} with a body ~matching authed level '${match.name}' — broken access control: the protected resource is served without proper authorization."
                    )
                )
            } else {
                findings.add(
                    Finding(
                        "high", "unauth_accessible",
                        "'${u.name}' returns ${u.status} (2xx/3xx) — the endpoint is reachable without authentication; confirm it is meant to be public."
                    )
                )
            }
        }

        // Same status across multiple authed identities but differing bodies → classic IDOR shape.
        if (allSameStatus && authLevels.size >= 2 && !allSimilar) {
            findings.add(
                Finding(
                    "info", "same_status_diff_body",
                    "All levels share status ${statuses.first()} but bodies differ — if these are different identities, confirm each only sees its own data (IDOR check)."
                )
            )
        }
        return findings
    }
}
