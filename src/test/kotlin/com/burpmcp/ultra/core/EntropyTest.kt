package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EntropyTest {

    @Test
    fun `empty string is zero`() {
        assertEquals(0.0, Entropy.shannon(""), 1e-9)
    }

    @Test
    fun `a single repeated character is zero`() {
        assertEquals(0.0, Entropy.shannon("aaaaaaaa"), 1e-9)
    }

    @Test
    fun `two equally likely symbols is one bit`() {
        assertEquals(1.0, Entropy.shannon("ab"), 1e-9)
        assertEquals(1.0, Entropy.shannon("aabb"), 1e-9)
    }

    @Test
    fun `diverse strings have higher entropy than repetitive ones`() {
        assertTrue(Entropy.shannon("a1B2c3D4z9Qx") > Entropy.shannon("aaaaaaaaaaaa"))
    }

    @Test
    fun `a realistic secret clears a 3 bit bar but the word test does not`() {
        assertTrue(Entropy.shannon("S3cr3tK3y_9aZ-x7Qp2Lm") >= 3.0)
        assertTrue(Entropy.shannon("test") < 3.0)
    }
}
