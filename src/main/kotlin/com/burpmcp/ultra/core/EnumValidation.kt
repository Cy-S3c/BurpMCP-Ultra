package com.burpmcp.ultra.core

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Validates closed-set ("enum-like") string parameters so an unrecognised value fails
 * loudly instead of silently no-op-ing, disabling a filter, or — worst — inverting a
 * security check (the bug class behind the proxy_history_search / scancheck findings).
 *
 * Returns `null` when the value is acceptable, or a standard `{"error": "..."}` JsonObject
 * naming the bad value and the allowed set. Matching is case-insensitive and trims blanks.
 */
object EnumValidation {

    /**
     * @param value the caller-supplied value (null = not provided).
     * @param allowed the accepted set (compared case-insensitively).
     * @param param the parameter name, for the error message.
     * @param required when true, a null/blank [value] is itself an error.
     */
    fun error(value: String?, allowed: Set<String>, param: String, required: Boolean = false): JsonObject? {
        val v = value?.trim()
        if (v.isNullOrEmpty()) {
            return if (required) err("Parameter '$param' is required", allowed) else null
        }
        val lower = allowed.map { it.lowercase() }.toSet()
        if (v.lowercase() in lower) return null
        return err("Parameter '$param' has invalid value '$value'", allowed)
    }

    private fun err(message: String, allowed: Set<String>): JsonObject = buildJsonObject {
        put("error", "$message. Allowed: ${allowed.sorted().joinToString(", ")}")
    }
}
