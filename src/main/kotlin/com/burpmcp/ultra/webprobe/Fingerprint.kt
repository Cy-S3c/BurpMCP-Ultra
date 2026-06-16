package com.burpmcp.ultra.webprobe

/**
 * Pure technology / WAF / framework fingerprinting from response headers and
 * body. Drives downstream payload selection (e.g. SSTI engine, WAF-bypass).
 */
object Fingerprint {

    /** @param headers header name -> value (case-insensitive); Set-Cookie values may be joined. */
    fun detect(headers: Map<String, String>, body: String): List<String> {
        val out = linkedSetOf<String>()
        val h = headers.mapKeys { it.key.lowercase() }

        h["server"]?.lowercase()?.let { s ->
            if ("nginx" in s) out.add("nginx")
            if ("apache" in s) out.add("apache")
            if ("iis" in s) out.add("iis")
            if ("cloudflare" in s) out.add("waf:cloudflare")
            if ("akamaighost" in s) out.add("waf:akamai")
        }
        h["x-powered-by"]?.lowercase()?.let { p ->
            if ("php" in p) out.add("php")
            if ("express" in p) out.add("express")
            if ("asp.net" in p) out.add("asp.net")
        }
        if (h.containsKey("cf-ray")) out.add("waf:cloudflare")
        if (h.keys.any { it.startsWith("x-akamai") }) out.add("waf:akamai")
        if (h.containsKey("x-sucuri-id") || h.containsKey("x-sucuri-cache")) out.add("waf:sucuri")
        if (h.keys.any { it.startsWith("x-iinfo") }) out.add("waf:imperva-incapsula")

        val cookies = h["set-cookie"] ?: ""
        if (cookies.contains("PHPSESSID", true)) out.add("php")
        if (cookies.contains("JSESSIONID", true)) out.add("java")
        if (cookies.contains("laravel_session", true)) out.add("laravel")
        if (cookies.contains("csrftoken", true)) out.add("django")
        if (cookies.contains("connect.sid", true)) out.add("express")
        if (cookies.contains("ASP.NET_SessionId", true)) out.add("asp.net")

        val b = body.take(50000)
        if (b.contains("/wp-content/", true) || b.contains("wp-json", true)) out.add("wordpress")
        if (b.contains("Drupal", true) || b.contains("/sites/default/files", true)) out.add("drupal")
        if (b.contains("__NEXT_DATA__", true)) out.add("next.js")
        return out.toList()
    }
}
