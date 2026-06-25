package com.burpmcp.ultra.core

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.burpmcp.ultra.transport.McpServerManager
import com.burpmcp.ultra.transport.DashboardServer
import com.burpmcp.ultra.transport.SecurityConfig
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.ui.BurpMcpUltraTab

class BurpMcpUltraExtension : BurpExtension {
    private lateinit var api: MontoyaApi
    private lateinit var serverManager: McpServerManager
    private lateinit var dashboardServer: DashboardServer
    private lateinit var eventBus: EventBus
    private lateinit var stateManager: StateManager
    private lateinit var uiTab: BurpMcpUltraTab

    override fun initialize(api: MontoyaApi) {
        this.api = api
        api.extension().setName("BurpMCP-Ultra")

        // Initialize event bus with ring buffer capacity
        eventBus = EventBus(maxBufferSize = 10000)

        // Initialize centralized state manager
        stateManager = StateManager()

        // Auth token shared by all three local servers. Required on every request
        // (header or ?token=) to defeat the "malicious website drives your localhost
        // MCP server" attack chain. Persisted in Burp preferences so it is stable
        // across reloads/restarts — generate once, reuse thereafter, so the operator
        // configures their MCP client only once.
        val prefs = api.persistence().preferences()
        val authToken = prefs.getString("mcp_auth_token")
            ?: SecurityConfig.generateToken().also { prefs.setString("mcp_auth_token", it) }

        // Create all bridge instances via factory
        val bridges = BridgeFactory.createAll(api, eventBus, stateManager)

        // Initialize and start MCP server on configured ports
        serverManager = McpServerManager(
            bridges = bridges,
            eventBus = eventBus,
            stateManager = stateManager,
            authToken = authToken,
            ssePort = 9876,
            httpPort = 9877,
            logging = api.logging()
        )
        serverManager.start()

        dashboardServer = DashboardServer(bridges, eventBus, stateManager, authToken, 9878, api.logging())
        dashboardServer.start()

        // Register Burp Suite event handlers for proxy, scanner, scope, websocket, and HTTP traffic
        registerBurpHandlers(bridges)

        // Initialize and register the UI tab
        uiTab = BurpMcpUltraTab(api, serverManager, eventBus, stateManager, bridges, authToken)
        api.userInterface().registerSuiteTab("BurpMCP-Ultra", uiTab.getComponent())

        // Register unload handler for clean shutdown
        api.extension().registerUnloadingHandler {
            uiTab.dispose()
            dashboardServer.stop()
            serverManager.stop()
            eventBus.clear()
            stateManager.cleanup()
            api.logging().logToOutput("BurpMCP-Ultra: Extension unloaded")
        }

        // Single startup banner with REAL counts (no more 137/134/121 drift, no
        // fake "Streamable HTTP"/"stdio" claims). uiTab.log() also writes to Burp's
        // output log, so one channel covers both surfaces.
        val (toolCount, resourceCount) = serverManager.registeredCounts()
        uiTab.log("INFO", "System", "BurpMCP-Ultra v${BuildInfo.VERSION} started")
        uiTab.log("INFO", "System", "MCP SSE (primary):   http://127.0.0.1:9876/  (root path '/', bearer token required)")
        uiTab.log("INFO", "System", "MCP SSE (secondary): http://127.0.0.1:9877/")
        uiTab.log("INFO", "System", "Dashboard:                 http://127.0.0.1:9878")
        uiTab.log("INFO", "System", "Tools: $toolCount  |  MCP Resources: $resourceCount")
        api.logging().raiseInfoEvent("BurpMCP-Ultra v${BuildInfo.VERSION} started (SSE 9876/9877, dashboard 9878)")

        // Do NOT log the auth token. uiTab.log() also writes to Burp's shared output
        // log, so logging the token would leak it into saved project files / screenshots.
        // The token and a ready-to-paste MCP client config are shown ONLY in the
        // BurpMCP-Ultra -> Server tab (same-process Swing UI), never in the log stream.
        uiTab.log("INFO", "System", "Auth token + MCP client config are shown in the BurpMCP-Ultra -> Server tab (kept out of the log).")
    }

    private fun registerBurpHandlers(bridges: BridgeFactory.Bridges) {
        // Register proxy request/response handlers for event collection
        api.proxy().registerRequestHandler(bridges.proxy.createRequestHandler())
        api.proxy().registerResponseHandler(bridges.proxy.createResponseHandler())

        // Register scanner audit issue handler (Pro edition only)
        try {
            api.scanner().registerAuditIssueHandler(bridges.scanner.createIssueHandler())
        } catch (e: Exception) {
            api.logging().logToOutput(
                "BurpMCP-Ultra: Scanner handler not available (Community Edition?)"
            )
        }

        // Register scope change handler for live scope tracking
        api.scope().registerScopeChangeHandler(bridges.scope.createScopeChangeHandler())

        // Register WebSocket creation handler
        api.websockets().registerWebSocketCreatedHandler(
            bridges.websocket.createWebSocketHandler()
        )

        // Register global HTTP handler for traffic interception rules
        api.http().registerHttpHandler(bridges.http.createGlobalHttpHandler())
    }
}
