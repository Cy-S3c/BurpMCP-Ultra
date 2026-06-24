package com.burpmcp.ultra.transport

import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult
import io.modelcontextprotocol.kotlin.sdk.types.TextResourceContents
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Central registry that wires the MCP resources onto an MCP [Server].
 *
 * MCP resources provide read-only, URI-addressed access to Burp Suite data.
 * Each resource is **static / read-on-demand**: reading it invokes the backing
 * bridge method and returns a current snapshot as JSON text.
 *
 * The MCP SDK 0.8.3 also supports subscribable resources (push updates), but
 * those are intentionally NOT implemented here — the "live" variants would be
 * true subscriptions backed by the EventBus and are out of scope. Clients that
 * want a current view simply read the static resource again.
 *
 * Registered resources (all `application/json`):
 *   - burp://proxy/history           - Recent proxy history (metadata page)
 *   - burp://proxy/websocket/history - Proxy WebSocket message history
 *   - burp://scanner/issues          - All scanner-reported audit issues
 *   - burp://sitemap                 - Site map entries
 *   - burp://scope                   - Current target scope configuration
 *   - burp://config/project          - Project-level configuration
 *   - burp://config/user             - User-level configuration
 *   - burp://organizer/items         - Organizer note items
 */
object ResourceRegistry {

    private const val JSON_MIME = "application/json"

    /** Default page size for the proxy history snapshot resource. */
    private const val PROXY_HISTORY_COUNT = 100

    /** Default page size for the proxy WebSocket history snapshot resource. */
    private const val WEBSOCKET_HISTORY_COUNT = 100

    /** Cap on the number of scanner issues returned by the issues resource. */
    private const val SCANNER_ISSUES_CAP = 500

    /** Cap on the number of site map entries returned by the sitemap resource. */
    private const val SITEMAP_MAX_RESULTS = 500

    /** Cap on the number of organizer items returned. */
    private const val ORGANIZER_MAX_RESULTS = 200

    /**
     * Registers all MCP resources on the given [server].
     * Called once per server instance during [McpServerManager.createMcpServer].
     */
    fun registerAll(
        server: Server,
        bridges: BridgeFactory.Bridges,
        eventBus: EventBus,
        stateManager: StateManager
    ) {
        // ---------------------------------------------------------------
        // burp://proxy/history
        // Recent proxy history as a JSON page (metadata-level: no full
        // request/response bodies) so the snapshot stays token-friendly.
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://proxy/history",
            name = "Proxy History",
            description = "Recent HTTP proxy history (metadata-level snapshot, most recent first)."
        ) {
            bridges.proxy.getHistory(
                startIndex = 0,
                count = PROXY_HISTORY_COUNT,
                host = null,
                method = null,
                statusCode = null,
                mimeType = null,
                inScopeOnly = false,
                includeRequest = false,
                includeResponse = false,
                statusCodeRange = null,
                maxResponseLength = null
            ).toString()
        }

        // ---------------------------------------------------------------
        // burp://proxy/websocket/history
        // Proxy WebSocket message history snapshot.
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://proxy/websocket/history",
            name = "Proxy WebSocket History",
            description = "Recorded WebSocket messages captured by the proxy."
        ) {
            bridges.proxy.getWebSocketHistory(
                startIndex = 0,
                count = WEBSOCKET_HISTORY_COUNT,
                host = null,
                direction = null
            ).toString()
        }

        // ---------------------------------------------------------------
        // burp://scanner/issues
        // All scanner-reported audit issues (capped).
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://scanner/issues",
            name = "Scanner Issues",
            description = "All scanner-reported audit issues with severity, confidence and affected URLs."
        ) {
            bridges.scanner.getAllIssues(null, null, null, SCANNER_ISSUES_CAP).toString()
        }

        // ---------------------------------------------------------------
        // burp://sitemap
        // Site map entries (metadata-level: no full request/response bodies).
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://sitemap",
            name = "Site Map",
            description = "Site map entries (URL, method, status, content type)."
        ) {
            bridges.sitemap.query(
                urlPrefix = null,
                searchPattern = null,
                maxResults = SITEMAP_MAX_RESULTS,
                includeRequest = false,
                includeResponse = false
            ).toString()
        }

        // ---------------------------------------------------------------
        // burp://scope
        // Current target scope configuration.
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://scope",
            name = "Target Scope",
            description = "Current target scope configuration (include/exclude rules)."
        ) {
            bridges.scope.getConfig().toString()
        }

        // ---------------------------------------------------------------
        // burp://config/project
        // Project-level configuration (full export).
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://config/project",
            name = "Project Configuration",
            description = "Project-level Burp Suite configuration exported as JSON."
        ) {
            // exportProjectConfig returns a raw JSON string of all project options.
            bridges.burpSuite.exportProjectConfig(emptyList())
        }

        // ---------------------------------------------------------------
        // burp://config/user
        // User-level configuration (full export).
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://config/user",
            name = "User Configuration",
            description = "User-level Burp Suite configuration exported as JSON."
        ) {
            // exportUserConfig returns a raw JSON string of all user options.
            bridges.burpSuite.exportUserConfig(emptyList())
        }

        // ---------------------------------------------------------------
        // burp://organizer/items
        // Organizer note items.
        // ---------------------------------------------------------------
        registerJsonResource(
            server,
            uri = "burp://organizer/items",
            name = "Organizer Items",
            description = "Items stored in Burp Suite's Organizer (bookmarked requests/notes)."
        ) {
            bridges.organizer.getItems(null, ORGANIZER_MAX_RESULTS).toString()
        }
    }

    /**
     * Registers a single read-on-demand JSON resource.
     *
     * The [produce] lambda is invoked on each read and must return a JSON
     * string. Any exception it throws is caught and converted into a small
     * JSON error payload so that one failing resource never breaks the read
     * (and never propagates an exception back through the SDK transport).
     *
     * The SDK signature confirmed via javap is:
     *   addResource(uri, name, description, mimeType, readHandler)
     * where readHandler is a suspend (ReadResourceRequest) -> ReadResourceResult.
     */
    private fun registerJsonResource(
        server: Server,
        uri: String,
        name: String,
        description: String,
        produce: () -> String
    ) {
        server.addResource(
            uri = uri,
            name = name,
            description = description,
            mimeType = JSON_MIME
        ) { request ->
            val text = try {
                produce()
            } catch (e: Exception) {
                buildJsonObject {
                    put("error", "Failed to read resource $uri")
                    put("message", e.message ?: e.javaClass.simpleName)
                }.toString()
            }

            ReadResourceResult(
                contents = listOf(
                    TextResourceContents(
                        text = text,
                        uri = request.uri,
                        mimeType = JSON_MIME
                    )
                )
            )
        }
    }
}
