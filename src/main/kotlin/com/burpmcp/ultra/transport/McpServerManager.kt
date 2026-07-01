package com.burpmcp.ultra.transport

import burp.api.montoya.logging.Logging
import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.core.BuildInfo
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
 * Both are plain MCP SSE transports: the SSE stream is the ROOT path "/" (GET) and
 * the back-channel is "/?sessionId=..." (POST) — NOT "/sse". There is no "Streamable
 * HTTP" or "stdio" transport — those were previously advertised but never implemented.
 *
 * @param bridges All bridge instances for tool/resource registration.
 * @param eventBus Shared event bus for event-related tools/resources.
 * @param stateManager Shared state for stateful tools.
 * @param bindHost Interface address to bind the transport servers to.
 * @param ssePort TCP port for the primary SSE transport (default 9876).
 * @param httpPort TCP port for the secondary SSE transport (default 9877).
 * @param logging Burp Suite logging API for startup/error messages.
 */
class McpServerManager(
    private val bridges: BridgeFactory.Bridges,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val authToken: String,
    private val bindHost: String = "127.0.0.1",
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
                version = BuildInfo.VERSION
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
     * SSE transport via [mcp]. The [mcp] extension mounts the SSE stream at the
     * ROOT path '/' (GET) with a POST back-channel keyed by a sessionId query
     * param — NOT '/sse'. Both require the auth token (Authorization: Bearer,
     * an mcp_token cookie, or a ?token= query param).
     */
    fun start() {
        startTransport("Primary SSE", ssePort) { sseServer = it }
        startTransport("Secondary SSE", httpPort) { httpServer = it }
    }

    /**
     * Launches one CIO transport on [port] and VERIFIES it actually bound.
     *
     * `start(wait = false)` returns before Ktor's CIO engine has bound the
     * socket, and a bind failure surfaces on the engine's own coroutines — not
     * the launching one — so a plain try/catch logs a false "started" while the
     * port never opens. That is the GitHub issue #2/#3 symptom: the UI shows
     * "running", 9876/9877 never listen, and there is no error. We therefore
     * actively probe the port and log a loud, actionable error if it didn't come
     * up (the usual cause is a JAR built with Java 22+).
     */
    private fun startTransport(
        label: String,
        port: Int,
        assign: (EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>) -> Unit
    ) {
        scope.launch {
            try {
                val server = embeddedServer(CIO, port = port, host = bindHost) {
                    installLocalhostSecurity(authToken, listOf(port), allowedSecurityHosts())
                    mcp(serverFactory())
                }
                server.start(wait = false)
                assign(server)

                if (verifyListening(port)) {
                    logging.logToOutput("BurpMCP-Ultra: $label transport listening on http://$bindHost:$port (MCP SSE endpoint is the root path '/', not '/sse')")
                } else {
                    logging.logToError(
                        "BurpMCP-Ultra: $label transport reported start() but $bindHost:$port is NOT listening. " +
                            "This is the GitHub issue #2/#3 symptom — almost always a JAR built with Java 22+ " +
                            "(Kotlin/Ktor/MCP-SDK incompatibility). Rebuild with a JDK 17-21 (NOT Burp's bundled Java 25)."
                    )
                }
            } catch (e: Exception) {
                logging.logToError("BurpMCP-Ultra: Failed to start $label transport on $bindHost:$port: ${e.message}")
                logging.logToError("BurpMCP-Ultra: Stack trace: ${e.stackTraceToString()}")
            }
        }
    }

    /** Probes [bindHost]:[port] for up to ~3s to confirm the engine actually bound the socket. */
    private suspend fun verifyListening(port: Int): Boolean {
        repeat(15) {
            try {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(bindHost, port), 200) }
                return true
            } catch (_: Exception) {
                kotlinx.coroutines.delay(200)
            }
        }
        return false
    }

    private fun allowedSecurityHosts(): List<String> =
        listOf(bindHost, "127.0.0.1", "localhost").distinct()

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
