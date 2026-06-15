package com.burpmcp.ultra.transport

import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*
import java.time.Instant

/**
 * Wraps all registered MCP tools on a [Server] so that every tool invocation
 * emits a `tool.called` event on the [EventBus] and records an activity entry
 * in the [StateManager] for the native Burp UI tab.
 *
 * Call [wrapAll] **after** all tools have been registered via [ToolRegistry].
 */
object ToolCallTracker {

    fun wrapAll(server: Server, eventBus: EventBus, stateManager: StateManager) {
        val toolsCopy = server.tools.values.toList()
        val toolNames = toolsCopy.map { it.tool.name }
        server.removeTools(toolNames)

        val wrappedTools = toolsCopy.map { registeredTool ->
            val originalHandler = registeredTool.handler
            val toolName = registeredTool.tool.name

            RegisteredTool(
                tool = registeredTool.tool,
                handler = { request: CallToolRequest ->
                    val startTime = System.nanoTime()
                    val startInstant = Instant.now()

                    val result: CallToolResult = originalHandler.invoke(request)

                    val elapsedMs = (System.nanoTime() - startTime) / 1_000_000

                    try {
                        recordToolCall(eventBus, stateManager, toolName, request, result, elapsedMs, startInstant)
                    } catch (_: Exception) {}

                    result
                }
            )
        }

        server.addTools(wrappedTools)
    }

    private fun recordToolCall(
        eventBus: EventBus,
        stateManager: StateManager,
        toolName: String,
        request: CallToolRequest,
        result: CallToolResult,
        elapsedMs: Long,
        timestamp: Instant
    ) {
        val argsJson = buildJsonObject {
            request.params.arguments?.forEach { (key, value) ->
                val truncated = value.toString().let {
                    if (it.length > 200) it.take(200) + "..." else it
                }
                put(key, truncated)
            }
        }

        val resultSummary = result.content
            ?.filterIsInstance<TextContent>()
            ?.firstOrNull()
            ?.text
            ?.let { if (it.length > 500) it.take(500) + "..." else it }
            ?: ""

        // Extract HTTP info from result JSON
        var url = ""
        var method = ""
        var host = ""
        var statusCode = 0
        try {
            val resultJson = result.content
                ?.filterIsInstance<TextContent>()
                ?.firstOrNull()
                ?.text
                ?.let { Json.parseToJsonElement(it).jsonObject }
            url = resultJson?.get("url")?.jsonPrimitive?.contentOrNull ?: ""
            method = resultJson?.get("method")?.jsonPrimitive?.contentOrNull ?: ""
            host = resultJson?.get("host")?.jsonPrimitive?.contentOrNull ?: ""
            statusCode = resultJson?.get("status_code")?.jsonPrimitive?.intOrNull ?: 0

            if (url.isEmpty()) url = resultJson?.get("request")?.jsonObject?.get("url")?.jsonPrimitive?.contentOrNull ?: ""
            if (method.isEmpty()) method = resultJson?.get("request")?.jsonObject?.get("method")?.jsonPrimitive?.contentOrNull ?: ""
            if (statusCode == 0) statusCode = resultJson?.get("response")?.jsonObject?.get("status_code")?.jsonPrimitive?.intOrNull ?: 0
        } catch (_: Exception) {}

        // Fallback from arguments
        if (url.isEmpty()) url = request.params.arguments?.get("url")?.jsonPrimitive?.contentOrNull ?: ""
        if (host.isEmpty()) host = request.params.arguments?.get("host")?.jsonPrimitive?.contentOrNull ?: ""
        if (method.isEmpty()) method = request.params.arguments?.get("method")?.jsonPrimitive?.contentOrNull ?: ""
        if (host.isEmpty() && url.isNotEmpty()) {
            try { host = java.net.URI(url).host ?: "" } catch (_: Exception) {}
        }

        val isError = result.isError ?: false

        // Record in StateManager for native Burp UI tab (with HttpRequestResponse from lastSentResult)
        val httpReqResp = lastSentResult.get()
        lastSentResult.remove()
        stateManager.addMcpActivity(
            toolName = toolName,
            timestamp = timestamp.toString(),
            durationMs = elapsedMs,
            method = method,
            url = url,
            host = host,
            statusCode = statusCode,
            isError = isError,
            argsSummary = argsJson.toString(),
            resultSummary = resultSummary,
            requestResponse = httpReqResp
        )

        // Emit event for web dashboard
        eventBus.emit("tool.called", buildJsonObject {
            put("tool_name", toolName)
            put("timestamp", timestamp.toString())
            put("duration_ms", elapsedMs)
            put("is_error", isError)
            put("arguments", argsJson)
            put("result_summary", resultSummary)
            put("url", url)
            put("method", method)
            put("host", host)
            put("status_code", statusCode)
        })

        // Durable, append-only audit trail for security-relevant calls: outbound
        // requests (have a url/host), destructive tools, and any error. Uses the
        // full arguments (capped per value), unlike the truncated UI/dashboard view.
        if (url.isNotEmpty() || host.isNotEmpty() || isError || com.burpmcp.ultra.safety.ActionPolicy.isDestructive(toolName)) {
            AuditLog.record(
                toolName, timestamp.toString(), elapsedMs, isError,
                request.params.arguments, url, host, method, statusCode
            )
        }
    }

    /**
     * Thread-local holder for the most recently sent HttpRequestResponse.
     * HttpBridge sets this after sendRequest (on the same thread that invoked the
     * tool handler) so the tracker can capture it without cross-call mis-attribution
     * under concurrency. The tracker's wrapped handler runs the original handler and
     * reads this value on the SAME thread, so a [ThreadLocal] correctly correlates them.
     */
    val lastSentResult = ThreadLocal<burp.api.montoya.http.message.HttpRequestResponse?>()
}
