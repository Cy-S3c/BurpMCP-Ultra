package com.burpmcp.ultra.safety

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class InterruptibleCharSequenceTest {

    @Test
    fun `delegates to the base sequence while not aborting`() {
        val seq = InterruptibleCharSequence("hello") { false }
        assertEquals(5, seq.length)
        assertEquals('h', seq[0])
        assertEquals("ell", seq.subSequence(1, 4).toString())
    }

    @Test
    fun `throws RegexTimeoutException once the abort predicate trips`() {
        var abort = false
        val seq = InterruptibleCharSequence("hello") { abort }
        assertEquals('h', seq[0])
        abort = true
        assertFailsWith<RegexTimeoutException> { seq[1] }
    }
}
