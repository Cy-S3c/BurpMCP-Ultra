package com.burpmcp.ultra.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OpenApiSchemaTest {

    private fun obj(s: String) = Json.parseToJsonElement(s).jsonObject

    // Note: \$ in a normal Kotlin string is a literal '$'.
    private val refs = mapOf(
        "#/components/schemas/User" to obj(
            "{\"type\":\"object\",\"properties\":{" +
                "\"id\":{\"type\":\"integer\"}," +
                "\"name\":{\"type\":\"string\"}," +
                "\"address\":{\"\$ref\":\"#/components/schemas/Address\"}}}"
        ),
        "#/components/schemas/Address" to obj("{\"type\":\"object\",\"properties\":{\"city\":{\"type\":\"string\"}}}")
    )

    @Test
    fun `resolves a ref into a nested object`() {
        val result = OpenApiSchema.example(obj("{\"\$ref\":\"#/components/schemas/User\"}"), refs).jsonObject
        assertEquals(1, result["id"]?.jsonPrimitive?.content?.toInt())
        assertEquals("test", result["name"]?.jsonPrimitive?.content)
        // nested $ref resolved
        assertEquals("test", result["address"]?.jsonObject?.get("city")?.jsonPrimitive?.content)
    }

    @Test
    fun `enum yields the first value`() {
        assertEquals("active", OpenApiSchema.example(obj("{\"type\":\"string\",\"enum\":[\"active\",\"banned\"]}"), refs).jsonPrimitive.content)
    }

    @Test
    fun `explicit example is honoured`() {
        assertEquals("foo", OpenApiSchema.example(obj("{\"type\":\"string\",\"example\":\"foo\"}"), refs).jsonPrimitive.content)
    }

    @Test
    fun `array of refs produces a one-element list`() {
        val arr = OpenApiSchema.example(obj("{\"type\":\"array\",\"items\":{\"\$ref\":\"#/components/schemas/Address\"}}"), refs).jsonArray
        assertEquals(1, arr.size)
        assertEquals("test", arr[0].jsonObject["city"]?.jsonPrimitive?.content)
    }

    @Test
    fun `allOf merges object properties`() {
        val merged = OpenApiSchema.example(
            obj("{\"allOf\":[{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"}}},{\"type\":\"object\",\"properties\":{\"b\":{\"type\":\"integer\"}}}]}"),
            refs
        ).jsonObject
        assertEquals("test", merged["a"]?.jsonPrimitive?.content)
        assertEquals(1, merged["b"]?.jsonPrimitive?.content?.toInt())
    }

    @Test
    fun `circular refs terminate without overflow`() {
        val circular = mapOf("#/components/schemas/Node" to obj("{\"type\":\"object\",\"properties\":{\"next\":{\"\$ref\":\"#/components/schemas/Node\"}}}"))
        // Should return some element and not throw / overflow.
        val result = OpenApiSchema.example(obj("{\"\$ref\":\"#/components/schemas/Node\"}"), circular)
        assertTrue(result is JsonObject)
    }

    @Test
    fun `string format hints produce realistic values`() {
        assertEquals("test@example.com", OpenApiSchema.example(obj("{\"type\":\"string\",\"format\":\"email\"}"), refs).jsonPrimitive.content)
    }
}
