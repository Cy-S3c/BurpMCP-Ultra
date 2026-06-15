package com.burpmcp.ultra.recon

import kotlin.math.abs

/** Pure decision helpers for content discovery + parameter mining. */
object ReconHeuristics {

    /**
     * Whether a discovered path is worth reporting, given a calibration baseline
     * (the response to a known-nonexistent path). Filters hard 404s and
     * soft-404s that mirror the catch-all baseline in status + size.
     */
    fun isInteresting(baselineStatus: Int, baselineLen: Int, status: Int, len: Int): Boolean {
        if (status == 0 || status == 404) return false
        if (status == baselineStatus && abs(len - baselineLen) < 64) return false
        return true
    }

    /** Whether a candidate parameter's unique marker is reflected in the response body. */
    fun reflects(body: String, marker: String): Boolean = body.contains(marker)
}
