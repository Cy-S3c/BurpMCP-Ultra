package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonInsertionPointsTest {

    @Test
    fun `enumerates nested object and array leaves with paths`() {
        val leaves = JsonInsertionPoints.leaves("""{"user":{"name":"alice","age":30},"tags":["a","b"]}""")
        assertEquals(
            listOf("user.name" to "alice", "user.age" to "30", "tags[0]" to "a", "tags[1]" to "b"),
            leaves
        )
    }

    @Test
    fun `non-json or empty returns no leaves`() {
        assertTrue(JsonInsertionPoints.leaves("not json at all").isEmpty())
        assertTrue(JsonInsertionPoints.leaves("").isEmpty())
    }

    @Test
    fun `handles a top-level array`() {
        assertEquals(listOf("[0]" to "1", "[1]" to "2"), JsonInsertionPoints.leaves("[1,2]"))
    }

    @Test
    fun `null and boolean leaves are still positions`() {
        assertEquals(listOf("x" to "", "y" to "true"), JsonInsertionPoints.leaves("""{"x":null,"y":true}"""))
    }
}
