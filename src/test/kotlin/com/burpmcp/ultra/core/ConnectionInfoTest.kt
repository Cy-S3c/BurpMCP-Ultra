package com.burpmcp.ultra.core

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Guards the two connection invariants that broke clients in GitHub issue #1:
 * the endpoint is the root path "/" (not "/sse") and the config always carries a token.
 */
class ConnectionInfoTest {

    @Test fun `sse url is the root path, never slash-sse`() {
        assertTrue(ConnectionInfo.primarySseUrl.endsWith(":9876/"), ConnectionInfo.primarySseUrl)
        assertTrue(ConnectionInfo.secondarySseUrl.endsWith(":9877/"), ConnectionInfo.secondarySseUrl)
        assertFalse(ConnectionInfo.primarySseUrl.contains("/sse"))
        assertFalse(ConnectionInfo.secondarySseUrl.contains("/sse"))
    }

    @Test fun `client config uses root url and a bearer token`() {
        val c = ConnectionInfo.clientConfigJson("TOK123")
        assertTrue(c.contains("\"url\":\"http://127.0.0.1:9876/\""), c)
        assertFalse(c.contains("/sse"))
        assertTrue(c.contains("\"Authorization\":\"Bearer TOK123\""), c)
        assertTrue(c.contains("\"type\":\"sse\""))
    }

    @Test fun `null token yields the placeholder, never a token-less config`() {
        val c = ConnectionInfo.clientConfigJson(null)
        assertTrue(c.contains("Bearer ${ConnectionInfo.TOKEN_PLACEHOLDER}"), c)
        assertTrue(c.contains("Authorization"))
    }
}
