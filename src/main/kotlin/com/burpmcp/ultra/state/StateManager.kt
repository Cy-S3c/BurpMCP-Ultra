package com.burpmcp.ultra.state

import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * A proxy interception/modification rule. Applied by the ProxyBridge when
 * matching requests or responses pass through Burp's proxy.
 *
 * @property ruleId Unique identifier (e.g. "prule-001").
 * @property type Whether this rule applies to "request" or "response".
 * @property matchHost Optional hostname glob to match (e.g. "*.example.com").
 * @property matchUrl Optional URL regex to match against the full URL.
 * @property matchMethod Optional HTTP method to match (e.g. "POST").
 * @property matchHeader Optional header name:value pattern to match.
 * @property matchBody Optional body content regex to match.
 * @property matchStatus Optional HTTP status code to match (response rules only).
 * @property action What to do when matched: "modify", "drop", or "tag".
 * @property modifyAddHeader Header to add (format "Name: Value").
 * @property modifyRemoveHeader Header name to remove.
 * @property modifyReplaceHeader Map of header names to replacement values.
 * @property modifyBodyRegex Regex pattern for body replacement.
 * @property modifyBodyReplacement Replacement string for body regex matches.
 * @property tagComment Comment to set on the proxy history item.
 * @property tagHighlight Highlight color to set on the proxy history item.
 * @property enabled Whether this rule is currently active.
 */
data class ProxyRule(
    val ruleId: String,
    val type: String,
    val matchHost: String? = null,
    val matchUrl: String? = null,
    val matchMethod: String? = null,
    val matchHeader: String? = null,
    val matchBody: String? = null,
    val matchStatus: Int? = null,
    val action: String,
    val modifyAddHeader: String? = null,
    val modifyRemoveHeader: String? = null,
    val modifyReplaceHeader: Map<String, String>? = null,
    val modifyBodyRegex: String? = null,
    val modifyBodyReplacement: String? = null,
    val tagComment: String? = null,
    val tagHighlight: String? = null,
    var enabled: Boolean = true
)

/**
 * A global HTTP traffic modification rule. Applied by the HttpBridge's
 * global HTTP handler to all outgoing requests or incoming responses.
 *
 * @property ruleId Unique identifier (e.g. "trule-001").
 * @property direction Whether this rule applies to "request" or "response".
 * @property matchUrl Optional URL regex to match.
 * @property matchHost Optional hostname glob to match.
 * @property matchHeader Optional header pattern to match.
 * @property modifyAddHeader Header to add (format "Name: Value").
 * @property modifyRemoveHeader Header name to remove.
 * @property modifyReplaceHeader Map of header names to replacement values.
 * @property enabled Whether this rule is currently active.
 */
data class TrafficRule(
    val ruleId: String,
    val direction: String,
    val matchUrl: String? = null,
    val matchHost: String? = null,
    val matchHeader: String? = null,
    val modifyAddHeader: String? = null,
    val modifyRemoveHeader: String? = null,
    val modifyReplaceHeader: Map<String, String>? = null,
    var enabled: Boolean = true
)

/**
 * A session handling rule that extracts a value from one response and
 * injects it into subsequent requests. Used for CSRF tokens, session
 * tokens, and other dynamic values.
 *
 * @property ruleName Human-readable name for this rule.
 * @property scope Where to apply: "all", "suite", or "custom".
 * @property scopePattern URL pattern when scope is "custom".
 * @property extractFrom Where to extract from: "header" or "body".
 * @property extractHeaderName Header name when extracting from headers.
 * @property extractRegex Regex with a capture group for extraction.
 * @property injectInto Where to inject: "header", "body", or "cookie".
 * @property injectName Name of the header/cookie/parameter to inject into.
 * @property injectValueTemplate Template string; "{value}" is replaced with the extracted value.
 * @property enabled Whether this rule is currently active.
 * @property lastExtractedValue The most recently extracted value (mutable for runtime updates).
 */
data class SessionRule(
    val ruleName: String,
    val scope: String,
    val scopePattern: String?,
    val extractFrom: String,
    val extractHeaderName: String?,
    val extractRegex: String,
    val injectInto: String,
    val injectName: String,
    val injectValueTemplate: String,
    var enabled: Boolean = true,
    var lastExtractedValue: String? = null
)

/**
 * Tracks a live WebSocket connection created through Burp's proxy or
 * programmatically via the WebSocket bridge.
 *
 * @property connectionId Unique identifier (e.g. "ws-001").
 * @property url The WebSocket URL.
 * @property createdAt ISO-8601 timestamp of connection creation.
 * @property status Current status: "connected", "closed", or "error".
 * @property messagesSent Counter of messages sent through this connection.
 * @property messagesReceived Counter of messages received on this connection.
 * @property messages Ordered list of messages exchanged on this connection.
 */
data class WebSocketConnection(
    val connectionId: String,
    val url: String,
    val createdAt: String,
    var status: String = "connected",
    val messagesSent: AtomicLong = AtomicLong(0),
    val messagesReceived: AtomicLong = AtomicLong(0),
    val messages: CopyOnWriteArrayList<WebSocketMessage> = CopyOnWriteArrayList()
) {
    /** Appends [message], evicting the oldest beyond [MAX_MESSAGES] so a busy socket can't exhaust memory. */
    fun record(message: WebSocketMessage) {
        messages.add(message)
        while (messages.size > MAX_MESSAGES) {
            try { messages.removeAt(0) } catch (_: Exception) { break }
        }
    }

    companion object { const val MAX_MESSAGES = 2000 }
}

/**
 * A single WebSocket message within a [WebSocketConnection].
 *
 * @property index Zero-based index within the connection's message list.
 * @property direction "client_to_server" or "server_to_client".
 * @property type "TEXT" or "BINARY".
 * @property payload The message content (binary payloads are base64-encoded).
 * @property length Length of the payload in bytes.
 * @property timestamp ISO-8601 timestamp of when the message was observed.
 */
data class WebSocketMessage(
    val index: Long,
    val direction: String,
    val type: String,
    val payload: String,
    val length: Int,
    val timestamp: String
)

/**
 * Tracks an active scanner crawl or audit task.
 *
 * @property taskId Unique identifier (e.g. "scan-001").
 * @property type "crawl" or "audit".
 * @property taskObject The actual Burp CrawlTask or AuditTask object.
 * @property createdAt ISO-8601 timestamp of task creation.
 */
data class ScanTask(
    val taskId: String,
    val type: String,
    val taskObject: Any,
    val createdAt: String
)

/**
 * Tracks a Burp Collaborator client instance and its associated server.
 *
 * @property clientId Unique identifier (e.g. "collab-001").
 * @property client The actual CollaboratorClient object from the Montoya API.
 * @property server The Collaborator server address.
 * @property createdAt ISO-8601 timestamp of client creation.
 */
data class CollaboratorClientState(
    val clientId: String,
    val client: Any,
    val server: String,
    val createdAt: String
)

/**
 * A WebSocket message interception rule. Applied by the WebSocket bridge
 * to intercept, modify, or tag messages on matching connections.
 *
 * @property ruleId Unique identifier (e.g. "wsrule-001").
 * @property matchUrl Optional URL regex to match against the WebSocket URL.
 * @property matchMessage Optional regex to match against message content.
 * @property direction Direction filter: "client_to_server", "server_to_client", or "both".
 * @property action What to do when matched: "modify", "drop", or "tag".
 * @property modifyRegex Regex pattern for message content replacement.
 * @property modifyReplacement Replacement string for regex matches.
 * @property tagComment Comment to attach to the matched message.
 * @property enabled Whether this rule is currently active.
 */
data class WebSocketInterceptRule(
    val ruleId: String,
    val matchUrl: String? = null,
    val matchMessage: String? = null,
    val direction: String = "both",
    val action: String = "tag",
    val modifyRegex: String? = null,
    val modifyReplacement: String? = null,
    val tagComment: String? = null,
    var enabled: Boolean = true
)

/**
 * A record of an MCP tool invocation, stored for UI display and Burp tool integration.
 *
 * @property id Monotonically increasing id for ordering.
 * @property toolName The MCP tool that was called.
 * @property timestamp ISO-8601 timestamp.
 * @property durationMs How long the call took.
 * @property method HTTP method (if applicable).
 * @property url Target URL (if applicable).
 * @property host Target host (if applicable).
 * @property statusCode HTTP response status (if applicable).
 * @property isError Whether the tool call returned an error.
 * @property argsSummary Truncated JSON of the tool arguments.
 * @property resultSummary Truncated JSON of the tool result.
 * @property requestResponse The actual Burp HttpRequestResponse (if this was an HTTP tool).
 */
data class McpActivityEntry(
    val id: Long,
    val toolName: String,
    val timestamp: String,
    val durationMs: Long,
    val method: String,
    val url: String,
    val host: String,
    val statusCode: Int,
    val isError: Boolean,
    val argsSummary: String,
    val resultSummary: String,
    val requestResponse: HttpRequestResponse? = null
)

/**
 * A structured, deduplicated finding recorded by the agent — its working memory
 * of confirmed/suspected issues, independent of Burp's native scanner issues.
 *
 * @property location Where the issue lives (e.g. "param:id", "header:X", "body").
 */
data class StoredFinding(
    val id: String,
    val type: String,
    val severity: String,
    val url: String,
    val location: String,
    val detail: String,
    val evidence: String,
    val createdAt: String
)

/**
 * Centralized, thread-safe state manager for all mutable runtime state.
 *
 * All collections use concurrent data structures so they can be safely
 * read and written from Burp handler threads, MCP request threads, and
 * the Ktor event loop concurrently.
 */
class StateManager {
    /** Active proxy interception/modification rules. */
    val proxyRules = CopyOnWriteArrayList<ProxyRule>()

    /** Active global HTTP traffic rules. */
    val trafficRules = CopyOnWriteArrayList<TrafficRule>()

    /** Active session handling rules. */
    val sessionRules = CopyOnWriteArrayList<SessionRule>()

    /** Live WebSocket connections keyed by connection id. */
    val websocketConnections = ConcurrentHashMap<String, WebSocketConnection>()

    /** Active scanner tasks keyed by task id. */
    val scanTasks = ConcurrentHashMap<String, ScanTask>()

    /** Active Collaborator clients keyed by client id. */
    val collaboratorClients = ConcurrentHashMap<String, CollaboratorClientState>()

    /** Agent-recorded structured findings (deduplicated working memory). */
    val findings = CopyOnWriteArrayList<StoredFinding>()

    /** Names of dynamically registered scan check extensions. */
    val registeredScanChecks = CopyOnWriteArrayList<String>()

    /**
     * Montoya [Registration] handles for scan checks registered via
     * [com.burpmcp.ultra.bridge.ScannerBridge.registerScanCheck], keyed by
     * check name. Retained so the registration is not leaked and the check
     * can be deregistered later (individually or on extension unload).
     */
    val scanCheckRegistrations = ConcurrentHashMap<String, Registration>()

    /** Names of dynamically registered payload processors. */
    val registeredPayloadProcessors = CopyOnWriteArrayList<String>()

    /** Rules for WebSocket message interception. */
    val websocketInterceptRules = CopyOnWriteArrayList<WebSocketInterceptRule>()

    /** Recent MCP tool call activity entries for the native Burp UI tab. */
    val mcpActivity = ConcurrentLinkedDeque<McpActivityEntry>()
    private val mcpActivityIdCounter = AtomicLong(0)

    /** Listeners notified when new MCP activity entries are added. */
    val mcpActivityListeners = CopyOnWriteArrayList<(McpActivityEntry) -> Unit>()

    /** Maximum number of MCP activity entries retained. */
    private val maxMcpActivityEntries = 2000

    /**
     * Records a new MCP tool call activity entry and notifies listeners.
     */
    fun addMcpActivity(
        toolName: String,
        timestamp: String,
        durationMs: Long,
        method: String,
        url: String,
        host: String,
        statusCode: Int,
        isError: Boolean,
        argsSummary: String,
        resultSummary: String,
        requestResponse: HttpRequestResponse? = null
    ): McpActivityEntry {
        val entry = McpActivityEntry(
            id = mcpActivityIdCounter.incrementAndGet(),
            toolName = toolName,
            timestamp = timestamp,
            durationMs = durationMs,
            method = method,
            url = url,
            host = host,
            statusCode = statusCode,
            isError = isError,
            argsSummary = argsSummary,
            resultSummary = resultSummary,
            requestResponse = requestResponse
        )
        mcpActivity.addFirst(entry)
        while (mcpActivity.size > maxMcpActivityEntries) {
            mcpActivity.pollLast()
        }
        mcpActivityListeners.forEach { listener ->
            try { listener(entry) } catch (_: Exception) {}
        }
        return entry
    }

    private val idCounter = AtomicLong(0)

    /**
     * Generates a unique id with the given [prefix], e.g. "prule-001".
     * The counter is shared across all id types to guarantee global uniqueness.
     */
    fun generateId(prefix: String): String {
        return "$prefix-${String.format("%03d", idCounter.incrementAndGet())}"
    }

    /**
     * Clears all state. Called during extension unload to release references
     * and allow garbage collection.
     */
    fun cleanup() {
        proxyRules.clear()
        trafficRules.clear()
        sessionRules.clear()
        websocketConnections.clear()
        scanTasks.clear()
        collaboratorClients.clear()
        findings.clear()
        registeredScanChecks.clear()
        // Deregister any live scan checks before dropping their handles so
        // they don't keep running after the extension unloads.
        scanCheckRegistrations.values.forEach { reg ->
            try { reg.deregister() } catch (_: Exception) {}
        }
        scanCheckRegistrations.clear()
        registeredPayloadProcessors.clear()
        websocketInterceptRules.clear()
        mcpActivity.clear()
        mcpActivityListeners.clear()
    }
}
