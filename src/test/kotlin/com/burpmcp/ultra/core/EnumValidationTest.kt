package com.burpmcp.ultra.core

import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EnumValidationTest {
    private val actions = setOf("modify", "drop", "tag")

    @Test fun `accepts a valid value, case and whitespace insensitive`() {
        assertNull(EnumValidation.error("drop", actions, "action"))
        assertNull(EnumValidation.error("  DROP ", actions, "action"))
    }

    @Test fun `rejects an unknown value, naming the value and the allowed set`() {
        val e = EnumValidation.error("block", actions, "action")
        assertNotNull(e)
        val msg = e!!["error"]!!.jsonPrimitive.content
        assertTrue(msg.contains("block"), msg)
        assertTrue(msg.contains("drop") && msg.contains("modify") && msg.contains("tag"), msg)
    }

    @Test fun `null or blank passes unless required`() {
        assertNull(EnumValidation.error(null, actions, "action"))
        assertNull(EnumValidation.error("   ", actions, "action"))
        assertNotNull(EnumValidation.error(null, actions, "action", required = true))
        assertNotNull(EnumValidation.error("", actions, "action", required = true))
    }
}
