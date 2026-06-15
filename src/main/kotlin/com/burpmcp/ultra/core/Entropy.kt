package com.burpmcp.ultra.core

import kotlin.math.ln

object Entropy {
    /**
     * Shannon entropy of [s] in bits per character (0.0 for empty). Used to
     * de-noise secret scanning: real keys/tokens have high per-char entropy,
     * while matches like "bearer test" are low and can be dropped.
     */
    fun shannon(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>()
        for (c in s) freq[c] = (freq[c] ?: 0) + 1
        val len = s.length.toDouble()
        var e = 0.0
        for (count in freq.values) {
            val p = count / len
            e -= p * (ln(p) / ln(2.0))
        }
        return e
    }
}
