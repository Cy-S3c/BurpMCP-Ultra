package com.burpmcp.ultra.graphql

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GraphQlTest {

    private fun obj(s: String) = Json.parseToJsonElement(s).jsonObject

    @Test
    fun `summarize reports introspection disabled when no schema`() {
        val s = GraphQl.summarize(obj("""{"data":{}}"""))
        assertFalse(s["introspection_enabled"]!!.jsonPrimitive.boolean)
    }

    @Test
    fun `summarize extracts query and mutation fields`() {
        val intro = obj(
            """{"data":{"__schema":{
               "queryType":{"name":"Query"},
               "mutationType":{"name":"Mutation"},
               "types":[
                 {"name":"Query","fields":[{"name":"users"},{"name":"me"}]},
                 {"name":"Mutation","fields":[{"name":"login"},{"name":"deleteUser"}]}
               ]}}}"""
        )
        val s = GraphQl.summarize(intro)
        assertTrue(s["introspection_enabled"]!!.jsonPrimitive.boolean)
        assertEquals("Query", s["query_type"]?.jsonPrimitive?.contentOrNull)
        val qf = s["query_fields"]!!.jsonArray.map { it.jsonPrimitive.content }
        val mf = s["mutation_fields"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertTrue("users" in qf && "me" in qf)
        assertTrue("login" in mf && "deleteUser" in mf)
    }

    @Test
    fun `extractSuggestions pulls did-you-mean field names`() {
        val msg = """Cannot query field "usr" on type "Query". Did you mean "users" or "user"?"""
        assertEquals(listOf("users", "user"), GraphQl.extractSuggestions(msg))
    }

    @Test
    fun `extractSuggestions returns empty when none`() {
        assertTrue(GraphQl.extractSuggestions("Syntax Error: Unexpected end of input").isEmpty())
    }
}
