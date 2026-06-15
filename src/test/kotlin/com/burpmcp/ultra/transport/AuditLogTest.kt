package com.burpmcp.ultra.transport

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuditLogTest {

    @Test
    fun `entry is valid json with the core fields`() {
        val line = AuditLog.buildEntry(
            "http_send_request", "2020-01-01T00:00:00Z", 12, false,
            mapOf("url" to JsonPrimitive("http://x")), "http://x", "x", "GET", 200
        )
        val o = Json.parseToJsonElement(line).jsonObject
        assertEquals("http_send_request", o["tool"]?.jsonPrimitive?.content)
        assertEquals(false, o["is_error"]?.jsonPrimitive?.boolean)
        assertEquals("http://x", o["url"]?.jsonPrimitive?.content)
        assertEquals(200, o["status_code"]?.jsonPrimitive?.content?.toInt())
        assertTrue(o.containsKey("args"))
    }

    @Test
    fun `long argument values are capped`() {
        val big = "A".repeat(20000)
        val line = AuditLog.buildEntry("t", "ts", 0, false, mapOf("body" to JsonPrimitive(big)), "", "", "", 0)
        val v = Json.parseToJsonElement(line).jsonObject["args"]?.jsonObject?.get("body")?.jsonPrimitive?.content!!
        assertTrue(v.length < 9000)
        assertTrue(v.contains("...["))
    }

    @Test
    fun `empty optional fields are omitted`() {
        val line = AuditLog.buildEntry("t", "ts", 0, false, null, "", "", "", 0)
        val o = Json.parseToJsonElement(line).jsonObject
        assertFalse(o.containsKey("url"))
        assertFalse(o.containsKey("status_code"))
        assertEquals("t", o["tool"]?.jsonPrimitive?.content)
    }
}
