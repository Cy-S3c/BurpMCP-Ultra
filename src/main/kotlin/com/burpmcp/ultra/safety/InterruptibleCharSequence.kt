package com.burpmcp.ultra.safety

/** Thrown when a guarded regex match exceeds its deadline (probable ReDoS). */
class RegexTimeoutException : RuntimeException("regex evaluation exceeded its time budget")

/**
 * A [CharSequence] that aborts (throws [RegexTimeoutException]) the instant
 * [abort] returns true. Wrapping a regex input in this lets the regex engine be
 * stopped mid-backtrack — the matcher reads characters as it works, so the
 * guard fires even inside catastrophic backtracking that would otherwise hang
 * a Burp proxy/HTTP thread.
 */
class InterruptibleCharSequence(
    private val base: CharSequence,
    private val abort: () -> Boolean
) : CharSequence {
    override val length: Int get() = base.length

    override fun get(index: Int): Char {
        if (abort()) throw RegexTimeoutException()
        return base[index]
    }

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
        InterruptibleCharSequence(base.subSequence(startIndex, endIndex), abort)

    override fun toString(): String = base.toString()
}
