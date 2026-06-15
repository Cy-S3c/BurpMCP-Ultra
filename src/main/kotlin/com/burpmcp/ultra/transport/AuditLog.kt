package com.burpmcp.ultra.transport

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File

/**
 * Durable, append-only audit trail for security-relevant MCP tool calls
 * (outbound requests, destructive tools, errors). Unlike the dashboard/UI
 * activity log this survives a Burp restart and keeps near-full arguments, so an
 * operator can reconstruct what an agent did.
 *
 * Writes JSON Lines to `~/.burpmcp-ultra-audit.jsonl`. Write failures are
 * recorded in [lastError] (surfaced by the extension) rather than swallowed.
 */
object AuditLog {
    private const val MAX_VALUE = 8000

    private val file: File = File(System.getProperty("user.home") ?: ".", ".burpmcp-ultra-audit.jsonl")

    @Volatile
    var lastError: String? = null
        private set

    fun path(): String = file.absolutePath

    /** Builds one JSONL audit record (pure; no I/O). Optional fields are omitted when blank. */
    fun buildEntry(
        toolName: String,
        timestampIso: String,
        durationMs: Long,
        isError: Boolean,
        args: Map<String, JsonElement>?,
        url: String,
        host: String,
        method: String,
        statusCode: Int
    ): String = buildJsonObject {
        put("ts", timestampIso)
        put("tool", toolName)
        put("duration_ms", durationMs)
        put("is_error", isError)
        if (url.isNotEmpty()) put("url", url)
        if (host.isNotEmpty()) put("host", host)
        if (method.isNotEmpty()) put("method", method)
        if (statusCode != 0) put("status_code", statusCode)
        put("args", buildJsonObject {
            args?.forEach { (k, v) ->
                val s = v.toString()
                put(k, if (s.length > MAX_VALUE) s.take(MAX_VALUE) + "...[+${s.length - MAX_VALUE}]" else s)
            }
        })
    }.toString()

    /** Appends an audit record to the log file. */
    fun record(
        toolName: String,
        timestampIso: String,
        durationMs: Long,
        isError: Boolean,
        args: Map<String, JsonElement>?,
        url: String,
        host: String,
        method: String,
        statusCode: Int
    ) {
        try {
            file.appendText(buildEntry(toolName, timestampIso, durationMs, isError, args, url, host, method, statusCode) + "\n")
        } catch (e: Exception) {
            lastError = e.message
        }
    }
}
