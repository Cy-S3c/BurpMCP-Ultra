package com.burpmcp.ultra.webprobe

import kotlin.test.Test
import kotlin.test.assertTrue

class FingerprintTest {

    @Test
    fun `detects server and x-powered-by`() {
        val t = Fingerprint.detect(mapOf("Server" to "nginx/1.25", "X-Powered-By" to "PHP/8.2"), "")
        assertTrue("nginx" in t)
        assertTrue("php" in t)
    }

    @Test
    fun `detects cloudflare WAF from cf-ray`() {
        assertTrue("waf:cloudflare" in Fingerprint.detect(mapOf("CF-RAY" to "abc-LHR"), ""))
    }

    @Test
    fun `detects framework from session cookie`() {
        assertTrue("java" in Fingerprint.detect(mapOf("Set-Cookie" to "JSESSIONID=ABC; Path=/"), ""))
    }

    @Test
    fun `detects wordpress from body`() {
        assertTrue("wordpress" in Fingerprint.detect(emptyMap(), """<link href="/wp-content/themes/x/style.css">"""))
    }

    @Test
    fun `empty input yields nothing`() {
        assertTrue(Fingerprint.detect(emptyMap(), "").isEmpty())
    }
}
