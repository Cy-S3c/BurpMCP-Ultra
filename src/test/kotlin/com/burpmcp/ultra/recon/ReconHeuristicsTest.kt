package com.burpmcp.ultra.recon

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReconHeuristicsTest {

    @Test
    fun `a 404 is never interesting`() {
        assertFalse(ReconHeuristics.isInteresting(404, 100, 404, 5000))
    }

    @Test
    fun `a response matching the catch-all baseline is not interesting`() {
        // baseline is a soft-404: 200 with len 1000; a path returning ~the same is noise
        assertFalse(ReconHeuristics.isInteresting(200, 1000, 200, 1010))
    }

    @Test
    fun `a differing status or size is interesting`() {
        assertTrue(ReconHeuristics.isInteresting(404, 0, 200, 1500))
        assertTrue(ReconHeuristics.isInteresting(200, 1000, 200, 9000))
        assertTrue(ReconHeuristics.isInteresting(404, 0, 403, 50))
    }

    @Test
    fun `reflection detects the marker in the body`() {
        assertTrue(ReconHeuristics.reflects("...zZmarker123...", "zZmarker123"))
        assertFalse(ReconHeuristics.reflects("nothing here", "zZmarker123"))
    }
}
