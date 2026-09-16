package com.burpmcp.ultra.core

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.burpmcp.ultra.transport.ActivityStore
import com.burpmcp.ultra.transport.AuditLog
import com.burpmcp.ultra.transport.BindHostPolicy
import com.burpmcp.ultra.transport.FindingsStore
import com.burpmcp.ultra.transport.McpServerManager
import com.burpmcp.ultra.transport.DashboardServer
import com.burpmcp.ultra.transport.PortPolicy
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

        // Register the unload handler EARLY — before anything binds a socket — with existence
        // guards, so that even if a later init step throws, Burp can still stop whatever started
        // and release the ports on the next reload. Without this, a partial init (e.g. a UI
        // exception after the servers started) orphans the listeners and the next load fails with
        // "Address already in use". Each step is guarded independently so one failure can't block
        // the rest of the teardown.
        api.extension().registerUnloadingHandler {
            try { if (::uiTab.isInitialized) uiTab.dispose() } catch (e: Exception) { api.logging().logToError("BurpMCP-Ultra: uiTab dispose failed: ${e.message}") }
            try { if (::dashboardServer.isInitialized) dashboardServer.stop() } catch (e: Exception) { api.logging().logToError("BurpMCP-Ultra: dashboard stop failed: ${e.message}") }
            try { if (::serverManager.isInitialized) serverManager.stop() } catch (e: Exception) { api.logging().logToError("BurpMCP-Ultra: server stop failed: ${e.message}") }
            try { eventBus.clear() } catch (_: Exception) {}
            try { stateManager.cleanup() } catch (_: Exception) {}
            api.logging().logToOutput("BurpMCP-Ultra: Extension unloaded")
        }

        // Restore the dashboard MCP activity from the durable store so it survives extension
        // reloads / Burp restarts / crashes (the in-memory deque + EventBus are otherwise lost
        // on every reload, wiping the dashboard). Repopulates the Swing tab (via the deque) AND
        // the web dashboard (by re-seeding the EventBus ring buffer with the historical events).
        try {
            val projectName = try { api.project().name() } catch (_: Exception) { "" }
            // Persistence is operator-controlled (pref mcp_persist_activity, default ON — issue #8).
            // When OFF, don't restore the saved history and don't write new entries (session-only).
            ActivityStore.enabled =
                try { api.persistence().preferences().getBoolean("mcp_persist_activity") } catch (_: Exception) { null } ?: true
            if (ActivityStore.enabled) {
                val restored = ActivityStore.load(projectName, stateManager.activityCapacity)
                stateManager.restoreMcpActivity(restored)
                restored.asReversed().forEach { e -> eventBus.emit("tool.called", ActivityStore.toEventData(e)) }
                ActivityStore.compact(ActivityStore.MAX_LINES)
                api.logging().logToOutput("BurpMCP-Ultra: restored ${restored.size} dashboard activity entries (project: ${projectName.ifEmpty { "default" }}); persistence ON → ${ActivityStore.path()}")
            } else {
                api.logging().logToOutput("BurpMCP-Ultra: MCP activity persistence is OFF (session only) — toggle it on the Server tab")
            }
            // Listener is always registered; ActivityStore.append() no-ops while persistence is OFF.
            stateManager.mcpActivityListeners.add { entry -> ActivityStore.append(entry, projectName) }
        } catch (e: Exception) {
            api.logging().logToError("BurpMCP-Ultra: activity restore failed: ${e.message}")
        }

        // Restore the agent's findings working memory from its durable store. Without this,
        // findings only lived in memory and were wiped by cleanup() on every extension
        // reload/Burp restart — while the (persisted) MCP activity log still showed the
        // historical findings_add calls, making it look like the findings vanished for no
        // reason. FindingsBridge.add() appends new ones via the listener below.
        try {
            val projectName = try { api.project().name() } catch (_: Exception) { "" }
            val restoredFindings = FindingsStore.load(projectName)
            if (restoredFindings.isNotEmpty()) stateManager.restoreFindings(restoredFindings)
            stateManager.findingsListeners.add { f -> FindingsStore.append(f, projectName) }
            api.logging().logToOutput(
                "BurpMCP-Ultra: restored ${restoredFindings.size} agent finding(s) (project: ${projectName.ifEmpty { "default" }}); store → ${FindingsStore.path()}"
            )
        } catch (e: Exception) {
            api.logging().logToError("BurpMCP-Ultra: findings restore failed: ${e.message}")
        }

        // Auth token shared by all three local servers. Required on every request
        // (header or ?token=) to defeat the "malicious website drives your localhost
        // MCP server" attack chain. Persisted in Burp preferences so it is stable
        // across reloads/restarts — generate once, reuse thereafter, so the operator
        // configures their MCP client only once.
        val prefs = api.persistence().preferences()
        val authToken = prefs.getString("mcp_auth_token")
            ?: SecurityConfig.generateToken().also { prefs.setString("mcp_auth_token", it) }

        // Configurable bind host (GitHub issue #4). The requested host comes from a JVM system
        // property (ops override), else a persisted Burp preference, else loopback. It is then
        // passed through the SECURITY GATE: a non-loopback bind exposes 149 Burp-driving tools to
        // the network, so it is only honored when the operator has explicitly opted in
        // (mcp_allow_remote_bind / -Dburpmcp.allowRemoteBind). Otherwise it is refused and
        // downgraded back to loopback. See BindHostPolicy.
        val requestedHost = System.getProperty("burpmcp.bindHost")?.trim()?.ifEmpty { null }
            ?: prefs.getString("mcp_bind_host")?.trim()?.ifEmpty { null }
            ?: "127.0.0.1"
        val allowRemoteBind = System.getProperty("burpmcp.allowRemoteBind")?.toBooleanStrictOrNull()
            ?: (try { prefs.getBoolean("mcp_allow_remote_bind") } catch (_: Exception) { null } ?: false)
        val bindDecision = BindHostPolicy.resolve(requestedHost, allowRemoteBind)
        val bindHost = bindDecision.effectiveHost

        // Create all bridge instances via factory
        val bridges = BridgeFactory.createAll(api, eventBus, stateManager)

        // Initialize the MCP + dashboard servers. From here on a socket may be bound, so if ANY
        // later init step throws we must stop them (see the early unload handler above) — otherwise
        // the partially-initialized instance orphans its listeners and the next reload fails with
        // "Address already in use".
        // Configurable ports, resolved on the same ladder as the bind host (system property, then
        // preference, then default). PortSwigger's own "MCP Server" extension also defaults to
        // 9876, so an operator running both needs a way out of the clash. See PortPolicy.
        fun port(sysProp: String, prefKey: String, default: Int): Int = PortPolicy.resolve(
            System.getProperty(sysProp),
            try { prefs.getString(prefKey) } catch (_: Exception) { null },
            default
        )
        val ssePort = port("burpmcp.ssePort", PortPolicy.PREF_SSE_PORT, PortPolicy.DEFAULT_SSE)
        val httpPort = port("burpmcp.httpPort", PortPolicy.PREF_HTTP_PORT, PortPolicy.DEFAULT_HTTP)
        val dashboardPort = port("burpmcp.dashboardPort", PortPolicy.PREF_DASHBOARD_PORT, PortPolicy.DEFAULT_DASHBOARD)

        serverManager = McpServerManager(
            bridges = bridges,
            eventBus = eventBus,
            stateManager = stateManager,
            authToken = authToken,
            bindHost = bindHost,
            ssePort = ssePort,
            httpPort = httpPort,
            logging = api.logging()
        )
        dashboardServer = DashboardServer(bridges, eventBus, stateManager, authToken, bindHost, dashboardPort, api.logging())
        try {
            serverManager.start()
            dashboardServer.start()

            // Register Burp Suite event handlers for proxy, scanner, scope, websocket, and HTTP traffic
            registerBurpHandlers(bridges)

            // Initialize and register the UI tab
            uiTab = BurpMcpUltraTab(api, serverManager, eventBus, stateManager, bridges, authToken, bindHost, ::rebindServers)
            api.userInterface().registerSuiteTab("BurpMCP-Ultra", uiTab.getComponent())
        } catch (t: Throwable) {
            api.logging().logToError(
                "BurpMCP-Ultra: initialization failed after the servers started — stopping them so " +
                    "the ports are released (avoids orphaned listeners): ${t.message}"
            )
            try { dashboardServer.stop() } catch (_: Exception) {}
            try { serverManager.stop() } catch (_: Exception) {}
            throw t
        }

        // Single startup banner with REAL counts (no more 137/134/121 drift, no
        // fake "Streamable HTTP"/"stdio" claims). uiTab.log() also writes to Burp's
        // output log, so one channel covers both surfaces.
        val (toolCount, resourceCount) = serverManager.registeredCounts()
        uiTab.log("INFO", "System", "BurpMCP-Ultra v${BuildInfo.VERSION} started")
        uiTab.log("INFO", "System", "MCP SSE (primary):   http://$bindHost:9876/  (root path '/', bearer token required)")
        uiTab.log("INFO", "System", "MCP SSE (secondary): http://$bindHost:9877/")
        uiTab.log("INFO", "System", "Dashboard:                 http://$bindHost:9878")
        uiTab.log("INFO", "System", "Tools: $toolCount  |  MCP Resources: $resourceCount")
        api.logging().raiseInfoEvent("BurpMCP-Ultra v${BuildInfo.VERSION} started on $bindHost (SSE 9876/9877, dashboard 9878)")

        // Surface the bind-host gate decision. A refused (downgraded) request and — especially —
        // an honored network exposure are security-relevant, so warn loudly and leave a durable
        // audit-log entry an operator can reconstruct later.
        if (bindDecision.downgraded) {
            val msg = bindDecision.message ?: "requested bind host was refused; using loopback"
            // A warning about a deliberate/edge choice, not a failure — Output tab, not Errors.
            api.logging().logToOutput("BurpMCP-Ultra: ⚠ $msg")
            uiTab.log("WARN", "System", msg)
        }
        if (bindDecision.exposed) {
            val msg = "SECURITY: ${bindDecision.message}"
            // Loud, but it's an operator-chosen exposure warning — Output tab, not Errors.
            api.logging().logToOutput("BurpMCP-Ultra: ⚠ $msg")
            uiTab.log("WARN", "System", msg)
            AuditLog.record(
                toolName = "server.remote_bind",
                timestampIso = java.time.Instant.now().toString(),
                durationMs = 0, isError = false, args = null,
                url = "", host = bindHost, method = "", statusCode = 0
            )
        }

        // Do NOT log the auth token. uiTab.log() also writes to Burp's shared output
        // log, so logging the token would leak it into saved project files / screenshots.
        // The token and a ready-to-paste MCP client config are shown ONLY in the
        // BurpMCP-Ultra -> Server tab (same-process Swing UI), never in the log stream.
        uiTab.log("INFO", "System", "Auth token + MCP client config are shown in the BurpMCP-Ultra -> Server tab (kept out of the log).")
    }

    /**
     * Live (no-reload) rebind of all three servers to [requestedHost], triggered by the Server-tab
     * "Save & Rebind Now" button. Runs the same [BindHostPolicy] gate as startup, restarts the
     * transports, and — on a network exposure — warns loudly and writes a durable audit entry,
     * exactly as the startup path does. Called OFF the Swing EDT by the UI.
     */
    private fun rebindServers(requestedHost: String, allowRemoteBind: Boolean): RebindOutcome {
        val d = BindHostPolicy.resolve(requestedHost, allowRemoteBind)
        val boundOk = try {
            val ok = serverManager.rebind(d.effectiveHost)
            dashboardServer.rebind(d.effectiveHost)
            ok
        } catch (e: Exception) {
            api.logging().logToError("BurpMCP-Ultra: live rebind to ${d.effectiveHost} failed: ${e.message}")
            false
        }
        if (d.downgraded) {
            api.logging().logToOutput("BurpMCP-Ultra: ⚠ ${d.message}")
        }
        if (d.exposed) {
            api.logging().logToOutput("BurpMCP-Ultra: ⚠ SECURITY: ${d.message}")
            AuditLog.record(
                toolName = "server.remote_bind",
                timestampIso = java.time.Instant.now().toString(),
                durationMs = 0, isError = false, args = null,
                url = "", host = d.effectiveHost, method = "", statusCode = 0
            )
        }
        api.logging().logToOutput(
            "BurpMCP-Ultra: live rebind to ${d.effectiveHost} — ${if (boundOk) "listening" else "NOT listening (check for a bind error)"}"
        )
        return RebindOutcome(d.effectiveHost, d.exposed, d.downgraded, boundOk, d.message)
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
