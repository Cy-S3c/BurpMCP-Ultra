package com.burpmcp.ultra.transport

import burp.api.montoya.logging.Logging
import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.core.BuildInfo
import com.burpmcp.ultra.core.ConnectionInfo
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import java.time.Instant

class DashboardServer(
    private val bridges: BridgeFactory.Bridges,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val authToken: String,
    private val port: Int = 9878,
    private val logging: Logging
) {
    private var server: EmbeddedServer<CIOApplicationEngine, CIOApplicationEngine.Configuration>? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val startTime = Instant.now()

    fun start() {
        scope.launch {
            try {
                server = embeddedServer(CIO, port = port, host = "127.0.0.1") {
                    // Host-header allowlist + locked CORS + token auth. "/" is
                    // token-exempt (so the browser can load the page); the page
                    // then injects the token for its own /api + /events calls.
                    installLocalhostSecurity(authToken, listOf(port), tokenExemptPaths = setOf("/"))
                    install(SSE)

                    routing {
                        // Dashboard HTML. Its same-origin /api + /events calls authenticate
                        // with an HttpOnly, SameSite=Strict cookie set here — NOT a token in
                        // the URL (URLs leak via browser history / Referer / access logs). The
                        // browser sends this cookie automatically on same-origin fetch + SSE.
                        get("/") {
                            call.response.cookies.append(
                                Cookie(
                                    name = "mcp_token",
                                    value = authToken,
                                    path = "/",
                                    httpOnly = true,
                                    extensions = mapOf("SameSite" to "Strict")
                                )
                            )
                            call.respondText(getDashboardHtml(), ContentType.Text.Html)
                        }

                        // SSE event stream
                        sse("/events") {
                            val subId = eventBus.subscribe(emptyList()) { event ->
                                launch {
                                    try {
                                        send(io.ktor.sse.ServerSentEvent(
                                            data = buildJsonObject {
                                                put("id", event.id)
                                                put("type", event.type)
                                                put("timestamp", event.timestamp)
                                                put("data", event.data)
                                            }.toString(),
                                            event = event.type
                                        ))
                                    } catch (_: Exception) {}
                                }
                            }
                            try {
                                // Keep connection alive
                                while (true) { delay(30000) }
                            } finally {
                                eventBus.unsubscribe(subId)
                            }
                        }

                        // REST API endpoints
                        route("/api") {
                            get("/stats") {
                                val uptimeSeconds = java.time.Duration.between(startTime, Instant.now()).seconds
                                call.respondText(buildJsonObject {
                                    put("uptime_seconds", uptimeSeconds)
                                    put("event_buffer_size", eventBus.size())
                                    put("proxy_rules", stateManager.proxyRules.size)
                                    put("traffic_rules", stateManager.trafficRules.size)
                                    put("session_rules", stateManager.sessionRules.size)
                                    put("scan_tasks", stateManager.scanTasks.size)
                                    put("websocket_connections", stateManager.websocketConnections.size)
                                    put("collaborator_clients", stateManager.collaboratorClients.size)
                                }.toString(), ContentType.Application.Json)
                            }

                            get("/events/recent") {
                                val limit = call.parameters["limit"]?.toIntOrNull() ?: 50
                                val events = eventBus.getEvents(sinceId = 0, maxEvents = limit)
                                call.respondText(buildJsonArray {
                                    events.takeLast(limit).forEach { evt ->
                                        add(buildJsonObject {
                                            put("id", evt.id)
                                            put("type", evt.type)
                                            put("timestamp", evt.timestamp)
                                            put("data", evt.data)
                                        })
                                    }
                                }.toString(), ContentType.Application.Json)
                            }

                            get("/proxy/recent") {
                                val limit = call.parameters["limit"]?.toIntOrNull() ?: 50
                                try {
                                    val history = bridges.proxy.getHistory(0, limit, null, null, null, null, false, true, true, null)
                                    call.respondText(history.toString(), ContentType.Application.Json)
                                } catch (e: Exception) {
                                    call.respondText("""{"error":"${e.message?.replace("\"", "'")}"}""", ContentType.Application.Json)
                                }
                            }

                            get("/rules") {
                                call.respondText(buildJsonObject {
                                    put("proxy_rules", buildJsonArray {
                                        stateManager.proxyRules.forEach { r ->
                                            add(buildJsonObject {
                                                put("id", r.ruleId)
                                                put("type", r.type)
                                                put("action", r.action)
                                                put("enabled", r.enabled)
                                            })
                                        }
                                    })
                                    put("traffic_rules", buildJsonArray {
                                        stateManager.trafficRules.forEach { r ->
                                            add(buildJsonObject {
                                                put("id", r.ruleId)
                                                put("direction", r.direction)
                                                put("enabled", r.enabled)
                                            })
                                        }
                                    })
                                    put("session_rules", buildJsonArray {
                                        stateManager.sessionRules.forEach { r ->
                                            add(buildJsonObject {
                                                put("name", r.ruleName)
                                                put("enabled", r.enabled)
                                            })
                                        }
                                    })
                                }.toString(), ContentType.Application.Json)
                            }
                        }
                    }
                }.also { it.start(wait = false) }

                logging.logToOutput("BurpMCP-Ultra: Dashboard server started on http://127.0.0.1:$port")
            } catch (e: Exception) {
                logging.logToError("BurpMCP-Ultra: Dashboard server failed: ${e.message}")
            }
        }
    }

    fun stop() {
        server?.stop(1000, 2000)
        scope.cancel()
    }

    private fun getDashboardHtml(): String {
        return DASHBOARD_HTML
    }

    companion object {
        val DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BurpMCP-Ultra Dashboard v2.0</title>
<style>
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-card: #1c2333;
    --bg-card-hover: #222d3f;
    --bg-detail: #151d2b;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --accent-blue: #58a6ff;
    --accent-green: #3fb950;
    --accent-orange: #d29922;
    --accent-red: #f85149;
    --accent-purple: #bc8cff;
    --accent-teal: #39d2c0;
    --accent-pink: #f778ba;
    --accent-yellow: #e3b341;
    --border: #30363d;
    --border-bright: #484f58;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;
    --radius: 8px;
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--font);background:var(--bg-primary);color:var(--text-primary);min-height:100vh;overflow-x:hidden;display:flex;flex-direction:column;}

/* ---- Header ---- */
.header{background:linear-gradient(135deg,#0d1b2a 0%,#1b2838 50%,#0f2027 100%);padding:12px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:200;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);}
.header-left{display:flex;align-items:center;gap:16px;}
.header h1{font-size:17px;font-weight:700;background:linear-gradient(135deg,var(--accent-blue),var(--accent-teal));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;white-space:nowrap;}
.header .version{font-size:10px;padding:2px 7px;border-radius:10px;background:rgba(88,166,255,0.15);color:var(--accent-blue);font-weight:600;letter-spacing:0.5px;}
.header-right{display:flex;align-items:center;gap:16px;font-size:12px;color:var(--text-secondary);}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent-green);box-shadow:0 0 6px var(--accent-green);flex-shrink:0;}
.status-dot.disconnected{background:var(--accent-red);box-shadow:0 0 6px var(--accent-red);}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
.status-dot{animation:pulse 2s ease-in-out infinite;}
.noise-toggle{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none;font-size:11px;padding:4px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg-card);transition:all 0.2s;}
.noise-toggle:hover{border-color:var(--accent-blue);}
.noise-toggle.active{border-color:var(--accent-green);background:rgba(63,185,80,0.1);}
.noise-toggle .indicator{width:6px;height:6px;border-radius:50%;background:var(--text-muted);transition:background 0.2s;}
.noise-toggle.active .indicator{background:var(--accent-green);}

/* ---- Stats Bar ---- */
.stats-bar{display:flex;gap:6px;padding:10px 24px;background:var(--bg-secondary);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center;}
.stat-pill{display:flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid var(--border);background:var(--bg-card);transition:all 0.2s;cursor:default;}
.stat-pill:hover{border-color:var(--border-bright);transform:translateY(-1px);}
.stat-pill .stat-num{font-family:var(--mono);font-size:12px;min-width:14px;text-align:center;}
.stat-pill .stat-label{color:var(--text-secondary);font-weight:500;}
.stat-pill.events .stat-num{color:var(--accent-blue);}
.stat-pill.scope .stat-num{color:var(--accent-green);}
.stat-pill.api .stat-num{color:var(--accent-orange);}
.stat-pill.auth .stat-num{color:var(--accent-red);}
.stat-pill.params .stat-num{color:var(--accent-yellow);}
.stat-pill.findings .stat-num{color:var(--accent-pink);}
.stat-pill.upload .stat-num{color:var(--accent-purple);}
.stat-pill.admin .stat-num{color:var(--accent-blue);}
.stat-pill.data .stat-num{color:var(--accent-teal);}
.stat-pill.hidden .stat-num{color:var(--text-muted);}
.stats-sep{width:1px;height:20px;background:var(--border);margin:0 4px;}
.stat-uptime{font-family:var(--mono);font-size:11px;color:var(--text-muted);margin-left:auto;padding:4px 10px;}

/* ---- Filter Bar ---- */
.filter-bar{display:flex;gap:8px;padding:10px 24px;background:var(--bg-secondary);border-bottom:1px solid var(--border);align-items:center;flex-wrap:wrap;}
.filter-group{display:flex;gap:2px;border-radius:var(--radius);overflow:hidden;border:1px solid var(--border);}
.filter-btn{padding:5px 12px;font-size:11px;font-weight:500;cursor:pointer;background:var(--bg-card);color:var(--text-secondary);border:none;transition:all 0.15s;white-space:nowrap;}
.filter-btn:hover{color:var(--text-primary);background:var(--bg-card-hover);}
.filter-btn.active{color:var(--accent-blue);background:rgba(88,166,255,0.12);}
.search-box{flex:1;min-width:180px;max-width:400px;padding:5px 12px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);font-size:12px;font-family:var(--mono);outline:none;transition:border-color 0.2s;}
.search-box:focus{border-color:var(--accent-blue);}
.search-box::placeholder{color:var(--text-muted);}
.filter-clear{padding:5px 10px;font-size:11px;cursor:pointer;background:none;color:var(--text-muted);border:1px solid var(--border);border-radius:var(--radius);transition:all 0.15s;}
.filter-clear:hover{color:var(--accent-red);border-color:var(--accent-red);}

/* ---- Main Activity Stream ---- */
.activity-container{flex:1;overflow-y:auto;padding:0;}
.activity-list{padding:4px 12px;}
.activity-item{display:grid;grid-template-columns:72px auto 1fr auto auto 28px;gap:8px;padding:7px 12px;border-radius:6px;font-size:11.5px;font-family:var(--mono);transition:background 0.12s;align-items:center;cursor:pointer;border:1px solid transparent;margin-bottom:1px;}
.activity-item:hover{background:var(--bg-card-hover);border-color:var(--border);}
.activity-item.selected{background:rgba(88,166,255,0.08);border-color:rgba(88,166,255,0.3);}
.activity-item.noise{opacity:0.35;}
.activity-time{color:var(--text-muted);font-size:10.5px;}
.activity-badges{display:flex;gap:3px;flex-wrap:nowrap;}
.badge{padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:0.3px;white-space:nowrap;flex-shrink:0;}
.badge-auth{background:rgba(248,81,73,0.18);color:var(--accent-red);}
.badge-api{background:rgba(210,153,34,0.18);color:var(--accent-orange);}
.badge-params{background:rgba(227,179,65,0.18);color:var(--accent-yellow);}
.badge-upload{background:rgba(188,140,255,0.18);color:var(--accent-purple);}
.badge-admin{background:rgba(88,166,255,0.18);color:var(--accent-blue);}
.badge-data{background:rgba(57,210,192,0.18);color:var(--accent-teal);}
.badge-scanner{background:rgba(248,81,73,0.18);color:var(--accent-red);}
.badge-scope{background:rgba(63,185,80,0.18);color:var(--accent-green);}
.badge-collab{background:rgba(188,140,255,0.18);color:var(--accent-purple);}
.badge-ws{background:rgba(57,210,192,0.18);color:var(--accent-teal);}
.badge-tool{background:rgba(63,185,80,0.18);color:var(--accent-green);}
.method-badge{padding:1px 6px;border-radius:3px;font-size:9.5px;font-weight:700;letter-spacing:0.3px;}
.method-GET{background:rgba(63,185,80,0.15);color:var(--accent-green);}
.method-POST{background:rgba(88,166,255,0.15);color:var(--accent-blue);}
.method-PUT{background:rgba(210,153,34,0.15);color:var(--accent-orange);}
.method-DELETE{background:rgba(248,81,73,0.15);color:var(--accent-red);}
.method-PATCH{background:rgba(188,140,255,0.15);color:var(--accent-purple);}
.method-OPTIONS{background:rgba(72,79,88,0.3);color:var(--text-muted);}
.method-HEAD{background:rgba(72,79,88,0.3);color:var(--text-muted);}
.method-tool{background:rgba(63,185,80,0.2);color:var(--accent-green);font-size:9px;letter-spacing:0.2px;}
.status-code{font-size:10.5px;font-weight:600;padding:1px 5px;border-radius:3px;text-align:center;min-width:28px;}
.status-2xx{color:var(--accent-green);background:rgba(63,185,80,0.1);}
.status-3xx{color:var(--accent-blue);background:rgba(88,166,255,0.1);}
.status-4xx{color:var(--accent-orange);background:rgba(210,153,34,0.1);}
.status-5xx{color:var(--accent-red);background:rgba(248,81,73,0.1);}
.activity-url{color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:11.5px;}
.activity-url .path{color:var(--text-primary);}
.activity-url .query{color:var(--accent-yellow);opacity:0.7;}
.activity-url .host{color:var(--text-muted);font-size:10px;margin-left:8px;}
.expand-icon{color:var(--text-muted);font-size:10px;transition:transform 0.2s;text-align:center;}
.activity-item.selected .expand-icon{transform:rotate(180deg);color:var(--accent-blue);}

/* ---- Detail Panel ---- */
.detail-panel{background:var(--bg-detail);border-top:2px solid var(--accent-blue);overflow:hidden;max-height:0;transition:max-height 0.3s ease-out;flex-shrink:0;}
.detail-panel.open{max-height:400px;}
.detail-inner{padding:16px 24px;display:grid;grid-template-columns:1fr 1fr;gap:16px;}
.detail-section h4{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:8px;font-weight:600;}
.detail-row{font-family:var(--mono);font-size:11.5px;padding:3px 0;display:flex;gap:8px;}
.detail-row .dl{color:var(--text-muted);min-width:80px;flex-shrink:0;}
.detail-row .dv{color:var(--text-primary);word-break:break-all;}
.detail-actions{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap;}
.detail-btn{padding:5px 12px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg-card);color:var(--text-secondary);font-size:11px;font-family:var(--font);cursor:pointer;transition:all 0.15s;display:flex;align-items:center;gap:5px;}
.detail-btn:hover{border-color:var(--accent-blue);color:var(--accent-blue);background:rgba(88,166,255,0.08);}
.detail-btn.copied{border-color:var(--accent-green);color:var(--accent-green);}
.detail-close{position:absolute;right:24px;top:16px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:16px;padding:4px 8px;border-radius:4px;}
.detail-close:hover{color:var(--text-primary);background:var(--bg-card);}
.detail-mcp{margin-top:12px;padding:10px 14px;background:var(--bg-primary);border-radius:var(--radius);border:1px solid var(--border);font-family:var(--mono);font-size:10.5px;color:var(--text-secondary);line-height:1.5;white-space:pre-wrap;word-break:break-all;max-height:140px;overflow-y:auto;cursor:pointer;transition:border-color 0.2s;}
.detail-mcp:hover{border-color:var(--accent-blue);}
.detail-hint{font-size:10px;color:var(--text-muted);margin-top:4px;font-style:italic;}
.detail-wrapper{position:relative;}

/* ---- Rules Tab ---- */
.tab-panel{display:none;flex:1;overflow-y:auto;padding:20px 24px;}
.tab-panel.active{display:block;}
.rules-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;}
.rule-section{background:var(--bg-card);border-radius:var(--radius);border:1px solid var(--border);padding:16px;}
.rule-section h3{font-size:13px;margin-bottom:10px;color:var(--text-primary);}
.rule-item{display:flex;justify-content:space-between;align-items:center;padding:6px 10px;background:var(--bg-primary);border-radius:var(--radius);margin-bottom:4px;font-size:11px;font-family:var(--mono);}
.rule-badge{padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;}
.rule-badge.active{background:rgba(63,185,80,0.15);color:var(--accent-green);}
.rule-badge.inactive{background:rgba(248,81,73,0.15);color:var(--accent-red);}

/* ---- Connections Tab ---- */
.conn-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;}
.conn-card{background:var(--bg-card);border-radius:var(--radius);border:1px solid var(--border);padding:16px;}
.conn-card h4{font-size:10px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;}
.conn-card .url{font-family:var(--mono);font-size:12px;color:var(--accent-blue);word-break:break-all;}

/* ---- Scrollbar ---- */
::-webkit-scrollbar{width:6px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
::-webkit-scrollbar-thumb:hover{background:var(--border-bright);}

/* ---- Empty state ---- */
.empty-state{text-align:center;padding:40px;color:var(--text-muted);font-size:12px;}

/* ---- Toast ---- */
.toast{position:fixed;bottom:20px;right:20px;padding:8px 16px;border-radius:var(--radius);background:var(--accent-green);color:#fff;font-size:12px;font-weight:600;opacity:0;transform:translateY(10px);transition:all 0.3s;z-index:999;pointer-events:none;}
.toast.show{opacity:1;transform:translateY(0);}

/* ---- Responsive ---- */
@media(max-width:768px){
    .header{padding:10px 12px;}
    .stats-bar,.filter-bar{padding:8px 12px;}
    .activity-item{grid-template-columns:60px auto 1fr auto 24px;font-size:10.5px;}
    .detail-inner{grid-template-columns:1fr;}
    .activity-list{padding:4px 6px;}
}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <div class="header-left">
        <h1>BurpMCP-Ultra</h1>
        <span class="version">v${BuildInfo.VERSION}</span>
    </div>
    <div class="header-right">
        <div class="status-dot" id="statusDot"></div>
        <span id="statusText">Connecting...</span>
        <span id="uptimeText" style="font-family:var(--mono);font-size:11px;">00:00:00</span>
        <div class="noise-toggle active" id="noiseToggle" onclick="toggleNoise()">
            <span class="indicator"></span>
            <span>Hide Noise</span>
        </div>
    </div>
</div>

<!-- Stats Bar -->
<div class="stats-bar">
    <div class="stat-pill events"><span class="stat-num" id="sEvents">0</span><span class="stat-label">Events</span></div>
    <div class="stat-pill scope"><span class="stat-num" id="sScope">0</span><span class="stat-label">In-Scope</span></div>
    <div class="stats-sep"></div>
    <div class="stat-pill api"><span class="stat-num" id="sApi">0</span><span class="stat-label">API</span></div>
    <div class="stat-pill auth"><span class="stat-num" id="sAuth">0</span><span class="stat-label">Auth</span></div>
    <div class="stat-pill params"><span class="stat-num" id="sParams">0</span><span class="stat-label">Params</span></div>
    <div class="stat-pill upload"><span class="stat-num" id="sUpload">0</span><span class="stat-label">Upload</span></div>
    <div class="stat-pill admin"><span class="stat-num" id="sAdmin">0</span><span class="stat-label">Admin</span></div>
    <div class="stat-pill data"><span class="stat-num" id="sData">0</span><span class="stat-label">Data</span></div>
    <div class="stats-sep"></div>
    <div class="stat-pill findings"><span class="stat-num" id="sFindings">0</span><span class="stat-label">Findings</span></div>
    <div class="stats-sep"></div>
    <div class="stat-pill scope" style="border-color:rgba(63,185,80,0.3);"><span class="stat-num" id="sToolCalls">0</span><span class="stat-label">MCP Calls</span></div>
    <div class="stat-pill hidden"><span class="stat-num" id="sHidden">0</span><span class="stat-label">Noise</span></div>
    <div class="stat-uptime" id="statUptime"></div>
</div>

<!-- Filter Bar -->
<div class="filter-bar">
    <div class="filter-group" id="typeFilter">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="proxy">Proxy</button>
        <button class="filter-btn" data-filter="scanner">Scanner</button>
        <button class="filter-btn" data-filter="scope">Scope</button>
        <button class="filter-btn" data-filter="tool">Tool</button>
        <button class="filter-btn" data-filter="collab">Collab</button>
        <button class="filter-btn" data-filter="websocket">WS</button>
    </div>
    <input type="text" class="search-box" id="searchBox" placeholder="Filter by URL, host, method...">
    <div class="filter-group" id="tabNav">
        <button class="filter-btn active" data-tab="stream">Activity Stream</button>
        <button class="filter-btn" data-tab="rules">Rules</button>
        <button class="filter-btn" data-tab="connections">Connections</button>
    </div>
    <button class="filter-clear" onclick="clearAll()">Clear All</button>
</div>

<!-- Activity Stream Tab -->
<div class="tab-panel active" id="panel-stream">
    <div class="activity-list" id="activityList">
        <div class="empty-state">Waiting for events from Burp Suite proxy...</div>
    </div>
</div>

<!-- Rules Tab -->
<div class="tab-panel" id="panel-rules">
    <div class="rules-grid" id="rulesGrid">
        <div class="rule-section"><h3>Proxy Rules</h3><div id="proxyRulesList"><div class="empty-state">No proxy rules</div></div></div>
        <div class="rule-section"><h3>Traffic Rules</h3><div id="trafficRulesList"><div class="empty-state">No traffic rules</div></div></div>
        <div class="rule-section"><h3>Session Rules</h3><div id="sessionRulesList"><div class="empty-state">No session rules</div></div></div>
    </div>
</div>

<!-- Connections Tab -->
<div class="tab-panel" id="panel-connections">
    <div class="conn-grid">
        <div class="conn-card"><h4>Primary MCP SSE (root path, token required)</h4><div class="url">${ConnectionInfo.primarySseUrl}</div></div>
        <div class="conn-card"><h4>Secondary MCP SSE (root path)</h4><div class="url">${ConnectionInfo.secondarySseUrl}</div></div>
        <div class="conn-card"><h4>Dashboard</h4><div class="url">${ConnectionInfo.dashboardUrl}</div></div>
        <div class="conn-card"><h4>Dashboard API - Proxy History</h4><div class="url">${ConnectionInfo.dashboardUrl}/api/proxy/recent?limit=50</div></div>
        <div class="conn-card"><h4>MCP Client Config — replace token from the Server tab</h4><div class="url" style="font-size:11px;">${ConnectionInfo.clientConfigJson(null)}</div></div>
    </div>
</div>

<!-- Detail Panel (fixed bottom) -->
<div class="detail-panel" id="detailPanel">
    <div class="detail-wrapper">
        <button class="detail-close" onclick="closeDetail()">&times;</button>
        <div class="detail-inner" id="detailInner"></div>
    </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
/* ==============================================================
   BurpMCP-Ultra Dashboard v2.0 - Interactive Bug Bounty Dashboard
   ============================================================== */

// ---- Noise filtering ----
var NOISE_DOMAINS = ['googleapis.com','gstatic.com','google.com/gen_204','generate_204',
    'detectportal','captive.apple','msftconnecttest','connectivity','ocsp.','crl.',
    'safebrowsing','update.googleapis','chrome-devtools','accounts.google','clients1.google',
    'play.google','fonts.googleapis','ajax.googleapis','maps.googleapis','translate.google',
    'ssl.gstatic','encrypted-tbn','beacons','analytics','doubleclick','googlesyndication',
    'googletagmanager','facebook.com/tr','bat.bing','clarity.ms'];

function isNoise(url) {
    if (!url) return false;
    var lower = url.toLowerCase();
    for (var i = 0; i < NOISE_DOMAINS.length; i++) {
        if (lower.indexOf(NOISE_DOMAINS[i]) !== -1) return true;
    }
    return false;
}

// ---- Attack vector detection ----
function detectVectors(url, method, contentType, statusCode, headers) {
    var vectors = [];
    var u = (url || '').toLowerCase();
    var ct = (contentType || '').toLowerCase();
    var m = (method || '').toUpperCase();
    var hdrs = (headers || '').toLowerCase();

    // AUTH
    if (/\/(login|auth|oauth|token|session|signin|signup|register|logout|password|reset|sso|saml|jwt|api-key|apikey)/.test(u)
        || hdrs.indexOf('authorization') !== -1 || hdrs.indexOf('x-api-key') !== -1
        || hdrs.indexOf('x-auth-token') !== -1) {
        vectors.push('auth');
    }
    // API
    if (/\/(api|v[0-9]+|graphql|rest|jsonrpc|grpc|webhook)[\/?]/.test(u)
        || ct.indexOf('application/json') !== -1 || ct.indexOf('application/graphql') !== -1
        || ct.indexOf('application/xml') !== -1) {
        vectors.push('api');
    }
    // PARAMS
    if (u.indexOf('?') !== -1 || (m === 'POST' || m === 'PUT' || m === 'PATCH')) {
        vectors.push('params');
    }
    // UPLOAD
    if (ct.indexOf('multipart/form-data') !== -1 || /\/(upload|import|attach|file)/.test(u)) {
        vectors.push('upload');
    }
    // ADMIN
    if (/\/(admin|manage|dashboard|console|debug|config|settings|internal|_admin|phpmy|phpmyadmin|wp-admin|cpanel)/.test(u)) {
        vectors.push('admin');
    }
    // DATA
    if (/\/(export|download|backup|dump|report|csv|xlsx)/.test(u)
        || /\.(sql|csv|json|xml|xlsx|xls|bak|zip|tar|gz|dump)(\?|$)/.test(u)) {
        vectors.push('data');
    }
    return vectors;
}

// ---- State ----
var events = [];
var MAX_EVENTS = 1000;
var noiseHidden = localStorage.getItem('burpmcp_noise') !== 'show';
var activeFilter = 'all';
var searchQuery = '';
var selectedEventId = null;
var counters = {events:0,scope:0,api:0,auth:0,params:0,upload:0,admin:0,data:0,findings:0,hidden:0,toolCalls:0};
var knownHosts = {};

// ---- DOM refs ----
var elList = document.getElementById('activityList');
var elDetail = document.getElementById('detailPanel');
var elDetailInner = document.getElementById('detailInner');
var elSearch = document.getElementById('searchBox');
var elToast = document.getElementById('toast');

// ---- Noise toggle ----
function toggleNoise() {
    noiseHidden = !noiseHidden;
    localStorage.setItem('burpmcp_noise', noiseHidden ? 'hide' : 'show');
    var btn = document.getElementById('noiseToggle');
    if (noiseHidden) btn.classList.add('active'); else btn.classList.remove('active');
    renderList();
}
document.getElementById('noiseToggle').classList.toggle('active', noiseHidden);

// ---- Tab switching ----
document.getElementById('tabNav').addEventListener('click', function(e) {
    var btn = e.target.closest('.filter-btn');
    if (!btn) return;
    var tab = btn.dataset.tab;
    document.querySelectorAll('#tabNav .filter-btn').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active');});
    var panel = document.getElementById('panel-' + tab);
    if (panel) panel.classList.add('active');
    if (tab === 'rules') fetchRules();
});

// ---- Type filter ----
document.getElementById('typeFilter').addEventListener('click', function(e) {
    var btn = e.target.closest('.filter-btn');
    if (!btn) return;
    activeFilter = btn.dataset.filter;
    document.querySelectorAll('#typeFilter .filter-btn').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    renderList();
});

// ---- Search ----
var searchTimer = null;
elSearch.addEventListener('input', function() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function() {
        searchQuery = elSearch.value.toLowerCase().trim();
        renderList();
    }, 150);
});

// ---- Add event ----
function addEvent(type, data, timestamp) {
    var ts = timestamp || new Date().toISOString();
    var time = new Date(ts);
    var timeStr = time.toLocaleTimeString('en-US', {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});

    var url = '', method = '', host = '', statusCode = 0, contentType = '', headersStr = '';
    var inScope = false, messageId = 0, mimeType = '';

    if (typeof data === 'object' && data !== null) {
        url = data.url || '';
        method = data.method || '';
        host = data.host || '';
        statusCode = data.status_code || 0;
        contentType = data.content_type || data.mime_type || mimeType || '';
        inScope = data.in_scope || false;
        messageId = data.message_id || 0;
        mimeType = data.mime_type || '';

        // For tool.called events, extract tool name as method-like display
        if (type === 'tool.called') {
            var toolName = data.tool_name || '';
            if (!method) method = toolName;
            if (!url && data.arguments) {
                url = data.arguments.url || data.arguments.raw_request || '';
                if (url.length > 100) url = url.substring(0, 100) + '...';
            }
            if (!host && data.arguments && data.arguments.host) host = data.arguments.host;
        }
    }

    var isNoisy = isNoise(url);
    var cat = mapTypeToCategory(type);
    var vectors = (cat === 'proxy' || cat === 'tool') ? detectVectors(url, method, contentType, statusCode, headersStr) : [];

    // Extract path
    var pathDisplay = url;
    try {
        if (url.indexOf('://') !== -1) {
            var u = new URL(url);
            pathDisplay = u.pathname + u.search;
            if (!host) host = u.hostname;
        }
    } catch(ex) {}

    // Build label for non-proxy events
    var label = '';
    if (cat === 'scanner') {
        label = (data && data.name) ? data.name : type;
        if (data && data.severity) label += ' [' + data.severity.toUpperCase() + ']';
        vectors = ['scanner'];
    } else if (cat === 'scope') {
        label = (data && typeof data === 'object') ? JSON.stringify(data).substring(0, 100) : String(data || type);
        vectors = ['scope'];
    } else if (cat === 'collab') {
        label = (data && data.type) ? data.type : 'Interaction';
        vectors = ['collab'];
    } else if (cat === 'websocket') {
        label = (data && data.url) ? data.url : type;
        vectors = ['ws'];
    } else if (type === 'tool.called' && data) {
        var tn = data.tool_name || 'unknown';
        var dur = data.duration_ms || 0;
        var isErr = data.is_error || false;
        label = tn + ' (' + dur + 'ms)' + (isErr ? ' ERROR' : '');
        vectors = ['tool'];
        // Use URL/method/status from the tool event data if available
        if (data.url) url = data.url;
        if (data.method && data.method !== tn) method = data.method;
        if (data.host) host = data.host;
        if (data.status_code) statusCode = data.status_code;
    } else if (!url && typeof data === 'object') {
        label = JSON.stringify(data).substring(0, 120);
    }

    var evt = {
        id: ++counters.events,
        type: type,
        category: cat,
        time: timeStr,
        timestamp: ts,
        method: method,
        url: url,
        path: pathDisplay,
        host: host,
        statusCode: statusCode,
        contentType: contentType,
        vectors: vectors,
        isNoise: isNoisy,
        inScope: inScope,
        messageId: messageId,
        label: label,
        raw: data
    };

    events.unshift(evt);
    if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;

    // Update counters
    if (isNoisy) counters.hidden++;
    if (inScope) { counters.scope++; knownHosts[host] = true; }
    if (host && !knownHosts[host]) { knownHosts[host] = !isNoisy; if (!isNoisy) counters.scope++; }
    vectors.forEach(function(v) { if (counters[v] !== undefined) counters[v]++; });
    if (cat === 'scanner') counters.findings++;
    if (type === 'tool.called') counters.toolCalls++;

    updateCounterDisplay();

    // Append to DOM directly for performance (if passes filter)
    if (passesFilter(evt)) {
        prependEventDOM(evt);
    }
}

function mapTypeToCategory(type) {
    if (type === 'tool.called') return 'tool';
    if (type.indexOf('proxy') !== -1) return 'proxy';
    if (type.indexOf('scanner') !== -1) return 'scanner';
    if (type.indexOf('scope') !== -1) return 'scope';
    if (type.indexOf('collaborator') !== -1 || type.indexOf('collab') !== -1) return 'collab';
    if (type.indexOf('websocket') !== -1) return 'websocket';
    return 'tool';
}

function passesFilter(evt) {
    if (noiseHidden && evt.isNoise) return false;
    if (activeFilter !== 'all' && evt.category !== activeFilter) return false;
    if (searchQuery) {
        var haystack = (evt.url + ' ' + evt.host + ' ' + evt.method + ' ' + evt.label).toLowerCase();
        if (haystack.indexOf(searchQuery) === -1) return false;
    }
    return true;
}

function updateCounterDisplay() {
    document.getElementById('sEvents').textContent = counters.events;
    document.getElementById('sScope').textContent = Object.keys(knownHosts).filter(function(h){return knownHosts[h];}).length;
    document.getElementById('sApi').textContent = counters.api;
    document.getElementById('sAuth').textContent = counters.auth;
    document.getElementById('sParams').textContent = counters.params;
    document.getElementById('sUpload').textContent = counters.upload;
    document.getElementById('sAdmin').textContent = counters.admin;
    document.getElementById('sData').textContent = counters.data;
    document.getElementById('sFindings').textContent = counters.findings;
    document.getElementById('sHidden').textContent = counters.hidden;
    document.getElementById('sToolCalls').textContent = counters.toolCalls;
}

// ---- Render full list (for filter changes) ----
function renderList() {
    while (elList.firstChild) elList.removeChild(elList.firstChild);
    var shown = 0;
    for (var i = 0; i < events.length; i++) {
        if (passesFilter(events[i])) {
            elList.appendChild(buildEventRow(events[i]));
            shown++;
            if (shown > 500) break;
        }
    }
    if (shown === 0) {
        var empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = events.length === 0 ? 'Waiting for events from Burp Suite proxy...' : 'No events match current filters';
        elList.appendChild(empty);
    }
}

function prependEventDOM(evt) {
    var empty = elList.querySelector('.empty-state');
    if (empty) empty.remove();
    elList.insertBefore(buildEventRow(evt), elList.firstChild);
    while (elList.children.length > 500) elList.removeChild(elList.lastChild);
}

function buildEventRow(evt) {
    var row = document.createElement('div');
    row.className = 'activity-item' + (evt.isNoise && !noiseHidden ? ' noise' : '') + (evt.id === selectedEventId ? ' selected' : '');
    row.dataset.eid = evt.id;
    row.onclick = function() { selectEvent(evt.id); };

    // Time
    var t = document.createElement('span');
    t.className = 'activity-time';
    t.textContent = evt.time;
    row.appendChild(t);

    // Badges
    var badges = document.createElement('span');
    badges.className = 'activity-badges';
    evt.vectors.forEach(function(v) {
        var b = document.createElement('span');
        b.className = 'badge badge-' + v;
        b.textContent = v.toUpperCase();
        badges.appendChild(b);
    });
    if (evt.vectors.length === 0) {
        var b = document.createElement('span');
        b.className = 'badge badge-' + evt.category;
        b.textContent = evt.category.toUpperCase();
        badges.appendChild(b);
    }
    row.appendChild(badges);

    // URL/label area
    var urlArea = document.createElement('span');
    urlArea.className = 'activity-url';
    if (evt.method && (evt.url || evt.category === 'tool')) {
        // Method badge — for tool events, show tool name
        var mb = document.createElement('span');
        var isToolEvt = evt.category === 'tool' && evt.type === 'tool.called';
        mb.className = isToolEvt ? 'method-badge method-tool' : ('method-badge method-' + evt.method);
        mb.textContent = evt.method;
        urlArea.appendChild(mb);
        urlArea.appendChild(document.createTextNode(' '));

        // Status if available
        if (evt.statusCode) {
            var sc = document.createElement('span');
            var scCls = evt.statusCode < 300 ? '2xx' : evt.statusCode < 400 ? '3xx' : evt.statusCode < 500 ? '4xx' : '5xx';
            sc.className = 'status-code status-' + scCls;
            sc.textContent = evt.statusCode;
            urlArea.appendChild(sc);
            urlArea.appendChild(document.createTextNode(' '));
        }

        // Path
        var pathParts = evt.path.split('?');
        var ps = document.createElement('span');
        ps.className = 'path';
        ps.textContent = pathParts[0];
        urlArea.appendChild(ps);
        if (pathParts[1]) {
            var qs = document.createElement('span');
            qs.className = 'query';
            qs.textContent = '?' + pathParts[1].substring(0, 60);
            urlArea.appendChild(qs);
        }

        // Host
        if (evt.host) {
            var hs = document.createElement('span');
            hs.className = 'host';
            hs.textContent = evt.host;
            urlArea.appendChild(hs);
        }
    } else {
        urlArea.textContent = evt.label || evt.type;
    }
    row.appendChild(urlArea);

    // Host column
    var hostCol = document.createElement('span');
    hostCol.style.cssText = 'color:var(--text-muted);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px;';
    hostCol.textContent = evt.host || '';
    row.appendChild(hostCol);

    // Expand
    var exp = document.createElement('span');
    exp.className = 'expand-icon';
    exp.textContent = '\u25BC';
    row.appendChild(exp);

    return row;
}

// ---- Select / Detail Panel ----
function selectEvent(eid) {
    if (selectedEventId === eid) {
        closeDetail();
        return;
    }
    selectedEventId = eid;

    // Update row highlights
    elList.querySelectorAll('.activity-item').forEach(function(r) {
        r.classList.toggle('selected', parseInt(r.dataset.eid) === eid);
    });

    var evt = events.find(function(e) { return e.id === eid; });
    if (!evt) return;

    // Build detail content
    while (elDetailInner.firstChild) elDetailInner.removeChild(elDetailInner.firstChild);

    // Left: request info
    var left = document.createElement('div');
    var h4L = document.createElement('h4');
    h4L.className = 'detail-section';
    h4L.textContent = 'REQUEST DETAILS';
    left.appendChild(h4L);

    var rows = [];
    if (evt.method) rows.push(['Method', evt.method]);
    if (evt.url) rows.push(['URL', evt.url]);
    if (evt.host) rows.push(['Host', evt.host]);
    if (evt.statusCode) rows.push(['Status', evt.statusCode + (evt.statusCode < 300 ? ' OK' : evt.statusCode < 400 ? ' Redirect' : evt.statusCode < 500 ? ' Client Error' : ' Server Error')]);
    if (evt.contentType) rows.push(['MIME', evt.contentType]);
    if (evt.messageId) rows.push(['Msg ID', '#' + evt.messageId]);
    if (evt.vectors.length) rows.push(['Vectors', evt.vectors.map(function(v){return v.toUpperCase();}).join(', ')]);
    rows.push(['Time', evt.time]);
    if (evt.inScope) rows.push(['Scope', 'In-scope']);

    rows.forEach(function(r) {
        var dr = document.createElement('div');
        dr.className = 'detail-row';
        var dl = document.createElement('span');
        dl.className = 'dl';
        dl.textContent = r[0];
        var dv = document.createElement('span');
        dv.className = 'dv';
        dv.textContent = r[1];
        dr.appendChild(dl);
        dr.appendChild(dv);
        left.appendChild(dr);
    });

    // Right: MCP tool actions
    var right = document.createElement('div');
    var h4R = document.createElement('h4');
    h4R.className = 'detail-section';
    h4R.textContent = 'MCP TOOL COMMANDS';
    right.appendChild(h4R);

    var hint = document.createElement('div');
    hint.className = 'detail-hint';
    hint.textContent = 'Click any command below to copy it. Paste and run in your MCP client.';
    right.appendChild(hint);

    // Tool commands
    var cmds = [];
    if (evt.url) {
        cmds.push({
            label: 'Send to Repeater',
            cmd: '{"tool":"proxy_send_to_repeater","arguments":{"message_id":' + (evt.messageId||0) + ',"tab_name":"Dashboard-' + evt.host + '"}}'
        });
        cmds.push({
            label: 'Active Scan',
            cmd: '{"tool":"scanner_active_scan","arguments":{"url":"' + evt.url.replace(/"/g, '\\"') + '"}}'
        });
        if (evt.host) {
            cmds.push({
                label: 'Add Host to Scope',
                cmd: '{"tool":"scope_include","arguments":{"prefix":"https://' + evt.host + '"}}'
            });
        }
        cmds.push({
            label: 'Search Proxy History',
            cmd: '{"tool":"proxy_history_search","arguments":{"pattern":"' + (evt.host || '').replace(/"/g, '\\"') + '","search_in":"both","max_results":20}}'
        });
        cmds.push({
            label: 'Get Full Request',
            cmd: '{"tool":"proxy_history","arguments":{"start_index":0,"count":1,"host":"' + (evt.host || '').replace(/"/g, '\\"') + '","include_request":true,"include_response":true}}'
        });
    }
    if (evt.category === 'scanner' && evt.raw) {
        cmds.push({
            label: 'View Issue Detail',
            cmd: '{"tool":"scanner_issues","arguments":{"url":"' + (evt.url || '').replace(/"/g, '\\"') + '"}}'
        });
    }

    // Action buttons
    var actions = document.createElement('div');
    actions.className = 'detail-actions';
    cmds.forEach(function(c) {
        var btn = document.createElement('button');
        btn.className = 'detail-btn';
        btn.textContent = c.label;
        btn.onclick = function(e) {
            e.stopPropagation();
            copyText(c.cmd);
            btn.classList.add('copied');
            btn.textContent = 'Copied!';
            setTimeout(function(){ btn.classList.remove('copied'); btn.textContent = c.label; }, 1500);
        };
        actions.appendChild(btn);
    });
    right.appendChild(actions);

    // Show first command as preview
    if (cmds.length > 0) {
        var pre = document.createElement('div');
        pre.className = 'detail-mcp';
        pre.textContent = cmds[0].cmd;
        pre.title = 'Click to copy';
        pre.onclick = function(e) {
            e.stopPropagation();
            copyText(cmds[0].cmd);
            showToast('Copied to clipboard');
        };
        right.appendChild(pre);
    }

    elDetailInner.appendChild(left);
    elDetailInner.appendChild(right);
    elDetail.classList.add('open');
}

function closeDetail() {
    selectedEventId = null;
    elDetail.classList.remove('open');
    elList.querySelectorAll('.activity-item.selected').forEach(function(r) { r.classList.remove('selected'); });
}

function copyText(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).catch(function(){});
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
    showToast('Copied to clipboard');
}

function showToast(msg) {
    elToast.textContent = msg;
    elToast.classList.add('show');
    setTimeout(function(){ elToast.classList.remove('show'); }, 2000);
}

function clearAll() {
    events = [];
    counters = {events:0,scope:0,api:0,auth:0,params:0,upload:0,admin:0,data:0,findings:0,hidden:0,toolCalls:0};
    knownHosts = {};
    updateCounterDisplay();
    closeDetail();
    renderList();
}

// ---- Auth: the mcp_token cookie (HttpOnly, SameSite=Strict) is sent automatically ----

// ---- SSE Connection ----
function connectSSE() {
    var es = new EventSource('/events');
    es.onopen = function() {
        document.getElementById('statusDot').classList.remove('disconnected');
        document.getElementById('statusText').textContent = 'Connected';
    };
    es.onerror = function() {
        document.getElementById('statusDot').classList.add('disconnected');
        document.getElementById('statusText').textContent = 'Reconnecting...';
    };

    var eventTypes = ['proxy.request','proxy.response','scanner.issue','scanner.task.status',
        'scope.changed','collaborator.interaction','websocket.created','websocket.message',
        'websocket.closed','http.request','http.response','proxy.intercept','proxy.rule.applied',
        'tool.called'];

    eventTypes.forEach(function(evtType) {
        es.addEventListener(evtType, function(e) {
            try {
                var parsed = JSON.parse(e.data);
                addEvent(evtType, parsed.data || parsed, parsed.timestamp);
            } catch(ex) {}
        });
    });

    es.onmessage = function(e) {
        try {
            var d = JSON.parse(e.data);
            addEvent(d.type || 'event', d.data || d, d.timestamp);
        } catch(ex) {}
    };
}

// ---- Fetch stats ----
function fetchStats() {
    fetch('/api/stats').then(function(r){return r.json();}).then(function(d) {
        var s = d.uptime_seconds || 0;
        var h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
        document.getElementById('uptimeText').textContent =
            String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');
        document.getElementById('statUptime').textContent =
            (h>0?h+'h ':'') + (m>0?m+'m ':'') + sec + 's uptime';
    }).catch(function(){});
}

// ---- Fetch rules ----
function fetchRules() {
    fetch('/api/rules').then(function(r){return r.json();}).then(function(d) {
        ['proxy','traffic','session'].forEach(function(type) {
            var key = type + '_rules';
            var el = document.getElementById(type + 'RulesList');
            var rules = d[key] || [];
            while (el.firstChild) el.removeChild(el.firstChild);
            if (rules.length === 0) {
                var empty = document.createElement('div');
                empty.className = 'empty-state';
                empty.textContent = 'No ' + type + ' rules active';
                el.appendChild(empty);
            } else {
                rules.forEach(function(r) {
                    var item = document.createElement('div');
                    item.className = 'rule-item';
                    var nameSpan = document.createElement('span');
                    nameSpan.textContent = r.id || r.name || 'unnamed';
                    item.appendChild(nameSpan);
                    var badge = document.createElement('span');
                    badge.className = 'rule-badge ' + (r.enabled ? 'active' : 'inactive');
                    badge.textContent = r.enabled ? 'ACTIVE' : 'OFF';
                    item.appendChild(badge);
                    el.appendChild(item);
                });
            }
        });
    }).catch(function(){});
}

// ---- Keyboard shortcuts ----
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeDetail();
    if (e.key === '/' && document.activeElement !== elSearch) {
        e.preventDefault();
        elSearch.focus();
    }
});

// ---- Initialize ----
connectSSE();
fetchStats();
fetchRules();
setInterval(fetchStats, 2000);
setInterval(fetchRules, 10000);

// Load initial proxy history from REST endpoint
fetch('/api/proxy/recent?limit=100').then(function(r){return r.json();}).then(function(d) {
    if (d.items && d.items.length > 0) {
        // Add in reverse so newest are first
        var items = d.items.slice().reverse();
        items.forEach(function(item) {
            var data = {
                url: item.url || '',
                method: item.method || '',
                host: item.host || '',
                status_code: item.status_code || 0,
                mime_type: item.response_mime_type || item.mime_type || '',
                in_scope: false,
                message_id: item.index || 0
            };
            addEvent('proxy.response', data, item.time || new Date().toISOString());
        });
    }
}).catch(function(){});
</script>
</body>
</html>
        """.trimIndent()
    }
}
