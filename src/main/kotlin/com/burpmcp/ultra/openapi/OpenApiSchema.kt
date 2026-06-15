package com.burpmcp.ultra.openapi

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Generates a realistic example JSON value from an OpenAPI/Swagger schema,
 * resolving `$ref`s against the spec's component/definition map. The previous
 * generator ignored `$ref` entirely, so every referenced body collapsed to
 * `"test"` or `{}` — making imported POST/PUT endpoints useless for fuzzing.
 *
 * Handles `$ref`, `allOf` (merge), `enum` (first value), `example`/`default`,
 * `format` hints, arrays, and nested objects, with a depth guard so circular
 * `$ref`s terminate instead of overflowing the stack.
 */
object OpenApiSchema {
    private const val MAX_DEPTH = 8

    /** Build the ref->schema lookup from an OpenAPI 3 (`components/schemas`) or Swagger 2 (`definitions`) spec. */
    fun buildRefs(spec: JsonObject): Map<String, JsonObject> {
        val m = HashMap<String, JsonObject>()
        runCatching {
            spec["components"]?.jsonObject?.get("schemas")?.jsonObject?.forEach { (k, v) -> m["#/components/schemas/$k"] = v.jsonObject }
        }
        runCatching {
            spec["definitions"]?.jsonObject?.forEach { (k, v) -> m["#/definitions/$k"] = v.jsonObject }
        }
        return m
    }

    /** Follows a single top-level `$ref` (if present), else returns the schema unchanged. */
    fun deref(schema: JsonObject, refs: Map<String, JsonObject>): JsonObject =
        schema["\$ref"]?.jsonPrimitive?.contentOrNull?.let { refs[it] } ?: schema

    /** Produces an example [JsonElement] for [schema]. */
    fun example(schema: JsonObject, refs: Map<String, JsonObject>, depth: Int = 0): JsonElement {
        if (depth > MAX_DEPTH) return JsonPrimitive("...")

        schema["\$ref"]?.jsonPrimitive?.contentOrNull?.let { ref ->
            val resolved = refs[ref] ?: return JsonPrimitive("test")
            return example(resolved, refs, depth + 1)
        }
        schema["example"]?.let { return it }
        schema["enum"]?.jsonArray?.firstOrNull()?.let { return it }
        schema["allOf"]?.jsonArray?.let { allOf ->
            return buildJsonObject {
                allOf.forEach { sub ->
                    val e = example(sub.jsonObject, refs, depth + 1)
                    if (e is JsonObject) e.forEach { (k, v) -> put(k, v) }
                }
            }
        }

        return when (schema["type"]?.jsonPrimitive?.contentOrNull) {
            "object" -> objectExample(schema, refs, depth)
            "array" -> buildJsonArray {
                val items = schema["items"]?.jsonObject
                add(if (items != null) example(items, refs, depth + 1) else JsonPrimitive("test"))
            }
            "string" -> JsonPrimitive(schema["default"]?.jsonPrimitive?.contentOrNull ?: stringByFormat(schema))
            "integer", "number" -> JsonPrimitive(schema["default"]?.jsonPrimitive?.intOrNull ?: 1)
            "boolean" -> JsonPrimitive(schema["default"]?.jsonPrimitive?.booleanOrNull ?: true)
            null -> if (schema.containsKey("properties")) objectExample(schema, refs, depth) else JsonPrimitive("test")
            else -> JsonPrimitive("test")
        }
    }

    private fun objectExample(schema: JsonObject, refs: Map<String, JsonObject>, depth: Int): JsonObject =
        buildJsonObject {
            schema["properties"]?.jsonObject?.forEach { (name, propSchema) ->
                runCatching { put(name, example(propSchema.jsonObject, refs, depth + 1)) }
            }
        }

    private fun stringByFormat(schema: JsonObject): String = when (schema["format"]?.jsonPrimitive?.contentOrNull) {
        "email" -> "test@example.com"
        "date-time" -> "2020-01-01T00:00:00Z"
        "date" -> "2020-01-01"
        "uuid" -> "00000000-0000-0000-0000-000000000000"
        "uri", "url" -> "https://example.com"
        "hostname" -> "example.com"
        "ipv4" -> "127.0.0.1"
        "password" -> "P@ssw0rd!"
        "byte" -> "dGVzdA=="
        else -> "test"
    }
}
