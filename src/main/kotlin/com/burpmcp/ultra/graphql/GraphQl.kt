package com.burpmcp.ultra.graphql

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Pure GraphQL recon helpers: a compact introspection query, a summarizer for
 * the introspection response, and "Did you mean" field-suggestion extraction
 * (schema enumeration even when introspection is disabled).
 */
object GraphQl {

    /** Compact introspection query — enough to enumerate root query/mutation fields. */
    const val INTROSPECTION_QUERY =
        "query IntrospectionQuery { __schema { queryType { name } mutationType { name } " +
            "subscriptionType { name } types { name fields { name } } } }"

    private val didYouMean = Regex("""Did you mean ([^?]+)\??""")
    private val quoted = Regex(""""([^"]+)"""")

    /** Summarizes an introspection response (`{data:{__schema:...}}`) into root types + field names. */
    fun summarize(json: JsonObject): JsonObject {
        val schema = json["data"]?.jsonObject?.get("__schema")?.jsonObject
            ?: return buildJsonObject { put("introspection_enabled", false) }

        val types = schema["types"]?.jsonArray ?: JsonArray(emptyList())
        fun fieldsOf(typeName: String?): List<String> {
            if (typeName == null) return emptyList()
            val t = types.firstOrNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull == typeName }?.jsonObject
            return t?.get("fields")?.jsonArray?.mapNotNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull } ?: emptyList()
        }

        val queryType = schema["queryType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull
        val mutationType = schema["mutationType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull
        val subscriptionType = schema["subscriptionType"]?.jsonObject?.get("name")?.jsonPrimitive?.contentOrNull

        return buildJsonObject {
            put("introspection_enabled", true)
            put("type_count", types.size)
            put("query_type", queryType)
            put("mutation_type", mutationType)
            if (subscriptionType != null) put("subscription_type", subscriptionType)
            put("query_fields", buildJsonArray { fieldsOf(queryType).forEach { add(it) } })
            put("mutation_fields", buildJsonArray { fieldsOf(mutationType).forEach { add(it) } })
        }
    }

    /** Extracts suggested field names from a "Did you mean ..." GraphQL error message (decoded). */
    fun extractSuggestions(decodedMessage: String): List<String> {
        val out = linkedSetOf<String>()
        didYouMean.findAll(decodedMessage).forEach { m ->
            quoted.findAll(m.groupValues[1]).forEach { out.add(it.groupValues[1]) }
        }
        return out.toList()
    }
}
