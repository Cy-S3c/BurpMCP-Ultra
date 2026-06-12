package com.burpmcp.ultra.bridge

/**
 * Decodes the queried hostname (QNAME) out of a raw DNS query message.
 *
 * `DnsDetails.query()` returns the full DNS request packet as raw bytes, so
 * calling `toString()` on it yields binary noise. This extracts the
 * human-readable name (e.g. `abc.oastify.com`) from the question section.
 */
object DnsQueryDecoder {

    /**
     * @param query the raw DNS query message bytes.
     * @return the dotted hostname from the question section, or `null` if the
     *   message is too short or the QNAME is malformed / truncated.
     */
    fun decodeQName(query: ByteArray): String? {
        // The DNS header is a fixed 12 bytes; the QNAME begins immediately after.
        if (query.size <= 12) return null

        val labels = mutableListOf<String>()
        var pos = 12
        while (pos < query.size) {
            val len = query[pos].toInt() and 0xFF
            if (len == 0) break                       // root label terminates the name
            if (len and 0xC0 == 0xC0) break           // compression pointer — not expected in a query QNAME; stop safely
            val start = pos + 1
            val end = start + len
            if (end > query.size) return null          // label runs past the buffer → malformed
            labels.add(String(query, start, len, Charsets.US_ASCII))
            pos = end
        }
        return if (labels.isEmpty()) null else labels.joinToString(".")
    }
}
