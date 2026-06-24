package com.burpmcp.ultra.transport

import burp.api.montoya.logging.Logging
import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.sse.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.*

/**
 * Manages the lifecycle of MCP server instances and their underlying
 * Ktor HTTP servers.
 *
 * Two SSE transports are exposed on separate ports so that multiple
 * MCP clients can connect independently:
 * - **Primary SSE** on [ssePort] (default 9876).
 * - **Secondary SSE** on [httpPort] (default 9877).
 *
 * Both are plain MCP SSE transports (GET /sse + POST /message). There is no
 * "Streamable HTTP" or "stdio" transport — those were previously advertised but
 * never implemented.
 *
 * @param bridges All bridge instances for tool/resource registration.
 * @param eventBus Shared event bus for event-related tools/resources.
 * @param stateManager Shared state for stateful tools.
 * @param ssePort TCP port for the primary SSE transport (default 9876).
 * @param httpPort TCP port for the secondary SSE transport (default 9877).
 * @param logging Burp Suite logging API for startup/error messages.
 */
class McpServerManager(
    private val bridges: BridgeFactory.Bridges,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val authToken: String,
    private val ssePort: Int = 9876,
    private val httpPort: Int = 9877,
    private val logging: Logging
) {
    private var sseServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private var httpServer: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Creates a fresh MCP [Server] instance with all tools and resources
     * registered. Each transport gets its own server instance so they
     * maintain independent session state.
     */
    fun createMcpServer(): Server {
        val server = Server(
            serverInfo = Implementation(
                name = "burpmcp-ultra",
                version = "2.1.0"
            ),
            options = ServerOptions(
                capabilities = ServerCapabilities(
                    tools = ServerCapabilities.Tools(listChanged = true),
                    resources = ServerCapabilities.Resources(
                        subscribe = true,
                        listChanged = true
                    )
                )
            )
        )

        // Register all tools and resources on this server instance
        ToolRegistry.registerAll(server, bridges, eventBus, stateManager)
        ResourceRegistry.registerAll(server, bridges, eventBus, stateManager)

        // Wrap all tools to emit tool.called events for dashboard + native UI visibility
        ToolCallTracker.wrapAll(server, eventBus, stateManager)

        return server
    }

    /**
     * Returns the REAL number of (tools, resources) actually registered, by
     * building a throwaway server and counting. Used for honest startup
     * reporting instead of a hardcoded count that drifts as tools change.
     */
    fun registeredCounts(): Pair<Int, Int> {
        val s = createMcpServer()
        return s.tools.size to s.resources.size
    }

    /**
     * Returns a factory function compatible with the MCP SDK's `mcp()` extension.
     * The SDK expects `(ServerSSESession) -> Server`.
     */
    private fun serverFactory(): (ServerSSESession) -> Server = { _ -> createMcpServer() }

    /**
     * Starts both transport servers asynchronously. Failures on one
     * transport do not prevent the other from starting.
     *
     * Each server is hardened via [installLocalhostSecurity] (Host-header
     * allowlist + locked CORS + per-session token) before mounting the MCP
     * SSE transport via [mcp]. The [mcp] extension auto-installs the Ktor SSE
     * plugin and registers GET /sse (streaming) and POST /message (back-channel)
     * endpoints. Both require the auth token.
     */
    fun start() {
        // Launch primary SSE transport
        scope.launch {
            try {
                sseServer = embeddedServer(CIO, port = ssePort, host = "127.0.0.1") {
                    installLocalhostSecurity(authToken, listOf(ssePort))
                    mcp(serverFactory())
                }.also { it.start(wait = false) }

                logging.logToOutput("BurpMCP-Ultra: SSE transport started on port $ssePort")
                logging.logToOutput("BurpMCP-Ultra: Connect MCP clients to http://127.0.0.1:$ssePort/sse")
            } catch (e: Exception) {
                logging.logToError(
                    "BurpMCP-Ultra: Failed to start SSE transport on port $ssePort: ${e.message}"
                )
                logging.logToError("BurpMCP-Ultra: Stack trace: ${e.stackTraceToString()}")
            }
        }

        // Launch secondary SSE transport on a separate port
        scope.launch {
            try {
                httpServer = embeddedServer(CIO, port = httpPort, host = "127.0.0.1") {
                    installLocalhostSecurity(authToken, listOf(httpPort))
                    mcp(serverFactory())
                }.also { it.start(wait = false) }

                logging.logToOutput(
                    "BurpMCP-Ultra: Secondary SSE transport started on port $httpPort"
                )
                logging.logToOutput("BurpMCP-Ultra: Connect MCP clients to http://127.0.0.1:$httpPort/sse")
            } catch (e: Exception) {
                logging.logToError(
                    "BurpMCP-Ultra: Failed to start secondary SSE transport on port $httpPort: ${e.message}"
                )
                logging.logToError("BurpMCP-Ultra: Stack trace: ${e.stackTraceToString()}")
            }
        }
    }

    /**
     * Gracefully stops both transport servers and cancels the coroutine scope.
     * Called from the extension unload handler.
     */
    fun stop() {
        sseServer?.stop(gracePeriodMillis = 1000, timeoutMillis = 2000)
        httpServer?.stop(gracePeriodMillis = 1000, timeoutMillis = 2000)
        scope.cancel()
        logging.logToOutput("BurpMCP-Ultra: MCP servers stopped")
    }
}
