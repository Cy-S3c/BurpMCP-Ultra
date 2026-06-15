package com.burpmcp.ultra.core

/** URL-encoding helpers beyond Burp's default (special-character-only) encoder. */
object UrlEncoding {

    /**
     * Percent-encodes EVERY byte of [data] (UTF-8), including otherwise-safe
     * characters — e.g. `"A-é"` -> `"%41%2D%C3%A9"`. Useful for WAF/parser
     * evasion where full encoding is required. This is the behaviour the
     * `encodeAll=true` flag promised but previously did not deliver.
     */
    fun percentEncodeAll(data: String): String =
        data.toByteArray(Charsets.UTF_8).joinToString("") { "%%%02X".format(it.toInt() and 0xFF) }
}
