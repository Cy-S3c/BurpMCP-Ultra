package com.burpmcp.ultra.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Enumerates scalar leaf nodes of a JSON body as fuzzable insertion points.
 * Burp's parsed BODY parameters do not descend into nested JSON, so without this
 * an agent can't target `user.address.city` or `items[2].id` for injection.
 */
object JsonInsertionPoints {

    /** Returns (path, value) for each scalar leaf in [jsonBody]; empty if it isn't JSON. */
    fun leaves(jsonBody: String): List<Pair<String, String>> {
        val root = try { Json.parseToJsonElement(jsonBody) } catch (_: Exception) { return emptyList() }
        val out = mutableListOf<Pair<String, String>>()
        walk(root, "", out)
        return out
    }

    private fun walk(el: JsonElement, path: String, out: MutableList<Pair<String, String>>) {
        when (el) {
            is JsonObject -> el.forEach { (k, v) -> walk(v, if (path.isEmpty()) k else "$path.$k", out) }
            is JsonArray -> el.forEachIndexed { i, v -> walk(v, "$path[$i]", out) }
            is JsonPrimitive -> out.add(path to (el.contentOrNull ?: "")) // JsonNull -> "" (still a position)
        }
    }
}
