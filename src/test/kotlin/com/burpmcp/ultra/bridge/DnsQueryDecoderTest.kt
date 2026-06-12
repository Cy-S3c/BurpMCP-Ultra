package com.burpmcp.ultra.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DnsQueryDecoderTest {

    /** Builds a minimal DNS query message: 12-byte header + QNAME + QTYPE + QCLASS. */
    private fun dnsQuery(vararg labels: String): ByteArray {
        val header = byteArrayOf(
            0x12, 0x34,             // transaction id
            0x01, 0x00,             // flags: standard query, recursion desired
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00              // ARCOUNT
        )
        val qname = labels.flatMap { label ->
            listOf(label.length.toByte()) + label.map { it.code.toByte() }
        } + 0x00.toByte()           // root terminator
        val footer = byteArrayOf(0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
        return header + qname.toByteArray() + footer
    }

    @Test
    fun `decodes a standard multi-label qname`() {
        val query = dnsQuery("abc", "example", "com")
        assertEquals("abc.example.com", DnsQueryDecoder.decodeQName(query))
    }

    @Test
    fun `decodes a long collaborator subdomain`() {
        val query = dnsQuery("rrm5a4gkkzf3k0ax55q0gfuylprffxxe24t5tnxc", "oastify", "com")
        assertEquals("rrm5a4gkkzf3k0ax55q0gfuylprffxxe24t5tnxc.oastify.com", DnsQueryDecoder.decodeQName(query))
    }

    @Test
    fun `returns null for input shorter than the DNS header`() {
        assertNull(DnsQueryDecoder.decodeQName(byteArrayOf(0x00, 0x01, 0x02)))
    }

    @Test
    fun `returns null when a label length runs past the buffer`() {
        // header + a label claiming length 5 but only 2 bytes of data follow
        val malformed = ByteArray(12) + byteArrayOf(0x05, 0x61, 0x62)
        assertNull(DnsQueryDecoder.decodeQName(malformed))
    }
}
