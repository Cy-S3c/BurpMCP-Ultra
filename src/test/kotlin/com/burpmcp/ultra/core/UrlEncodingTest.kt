package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertEquals

class UrlEncodingTest {

    @Test
    fun `encodes plain ascii`() {
        assertEquals("%41%42", UrlEncoding.percentEncodeAll("AB"))
    }

    @Test
    fun `encodes even otherwise-safe characters`() {
        assertEquals("%2D%2E%5F", UrlEncoding.percentEncodeAll("-._"))
    }

    @Test
    fun `encodes multibyte utf8 as its byte sequence`() {
        assertEquals("%C3%A9", UrlEncoding.percentEncodeAll("é"))
    }
}
