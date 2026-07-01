package com.burpmcp.ultra.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import com.burpmcp.ultra.bridge.BridgeFactory
import com.burpmcp.ultra.core.ConnectionInfo
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.McpActivityEntry
import com.burpmcp.ultra.state.StateManager
import com.burpmcp.ultra.transport.McpServerManager
import kotlinx.serialization.json.*
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import java.text.NumberFormat
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel

/**
 * Native multi-tab Burp Suite UI for BurpMCP-Ultra.
 *
 * Tabs:
 * 1. MCP Activity   — Real-time tool call monitor with Burp request/response editors
 * 2. Proxy Explorer  — Browse/search proxy history with Burp-native viewers
 * 3. Scanner         — Live scanner findings with severity/confidence display
 * 4. Collaborator    — Create OOB clients, generate payloads, poll interactions
 * 5. Rules           — View/manage proxy, traffic, and session rules
 * 6. Server          — Server config, connection info, stats
 */
class BurpMcpUltraTab(
    private val api: MontoyaApi,
    private val serverManager: McpServerManager,
    private val eventBus: EventBus,
    private val stateManager: StateManager,
    private val bridges: BridgeFactory.Bridges,
    private val authToken: String,
    private val bindHost: String
) {
    companion object {
        const val MAX_TABLE_ROWS = 2000
        private val TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
        private val NUMBER_FORMAT: NumberFormat = NumberFormat.getIntegerInstance()
    }

    private val mainPanel = JPanel(BorderLayout(0, 0))
    private val tabbedPane = JTabbedPane(JTabbedPane.TOP)
    private val serverStartTime = System.currentTimeMillis()
    private val totalToolCalls = AtomicLong(0)
    private val totalErrors = AtomicLong(0)
    private val perToolCounts = ConcurrentHashMap<String, AtomicLong>()
    private val refreshTimer: Timer

    // Fetch buttons captured so tabs can lazily auto-load on first view.
    private var proxyFetchButton: JButton? = null
    private var scannerFetchButton: JButton? = null

    // Activity tab state
    private val activityById = ConcurrentHashMap<Long, McpActivityEntry>()
    private var activityFilter = "all"
    private var activitySearch = ""

    init {
        tabbedPane.font = tabbedPane.font.deriveFont(12f)
        tabbedPane.addTab("MCP Activity", buildActivityTab())
        tabbedPane.addTab("Proxy Explorer", buildProxyTab())
        tabbedPane.addTab("Scanner", buildScannerTab())
        tabbedPane.addTab("Collaborator", buildCollaboratorTab())
        tabbedPane.addTab("Rules", buildRulesTab())
        tabbedPane.addTab("Server", buildServerTab())
        mainPanel.add(tabbedPane, BorderLayout.CENTER)

        wireActivityListener()

        refreshTimer = Timer(1500) {
            refreshServerTab()
            refreshRulesTab()
            // Activity stats (incl. Events count from the event bus) must refresh on
            // the timer too — otherwise the bar is frozen until an MCP tool call fires
            // the activity listener, so "Events: 0" never updates from proxy traffic.
            updateActivityStats()
        }
        refreshTimer.isRepeats = true
        refreshTimer.start()

        // Lazily load Proxy/Scanner the first time each tab is shown, so they are
        // not permanently blank waiting for a manual Fetch click (tab order:
        // 0 Activity, 1 Proxy, 2 Scanner, 3 Collaborator, 4 Rules, 5 Server).
        var proxyLoaded = false
        var scannerLoaded = false
        tabbedPane.addChangeListener {
            when (tabbedPane.selectedIndex) {
                1 -> if (!proxyLoaded) { proxyLoaded = true; proxyFetchButton?.doClick() }
                2 -> if (!scannerLoaded) { scannerLoaded = true; scannerFetchButton?.doClick() }
            }
        }

        api.userInterface().applyThemeToComponent(mainPanel)
    }

    fun getComponent(): Component = mainPanel
    fun dispose() {
        refreshTimer.stop()
        stateManager.mcpActivityListeners.clear()
    }
    fun log(level: String, category: String, message: String) {
        if (level == "INFO") api.logging().logToOutput("BurpMCP-Ultra: $message")
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 1: MCP ACTIVITY
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var activityTableModel: DefaultTableModel
    private lateinit var activityTable: JTable
    private lateinit var activityRequestEditor: HttpRequestEditor
    private lateinit var activityResponseEditor: HttpResponseEditor
    private lateinit var activityDetailInfo: JTextArea
    private lateinit var activityStatsLabel: JLabel

    private val httpToolNames = setOf(
        "http_send_request", "http_send_requests_parallel", "http_send_request_chain",
        "http_fuzz", "http_send_raw_bytes", "http_race", "http_cookie_jar_get",
        "http_cookie_jar_set", "http_analyze_keywords", "http_analyze_variations",
        "http_set_traffic_rule", "http_list_traffic_rules", "http_remove_traffic_rule",
        "auth_diff", "api_import_openapi"
    )
    private val proxyToolNames = setOf(
        "proxy_history", "proxy_history_search", "proxy_websocket_history",
        "proxy_websocket_history_search", "proxy_intercept_enable", "proxy_intercept_disable",
        "proxy_intercept_status", "proxy_annotate", "proxy_set_request_rule",
        "proxy_set_response_rule", "proxy_list_rules", "proxy_remove_rule", "proxy_auto_auth"
    )
    private val scannerToolNames = setOf(
        "scanner_start_crawl", "scanner_start_audit", "scanner_task_status",
        "scanner_task_list", "scanner_task_delete", "scanner_task_issues",
        "scanner_get_all_issues", "scanner_generate_report", "scanner_create_issue",
        "scanner_import_bcheck", "scanner_register_check", "scanner_unregister_check",
        "bcheck_create", "bcheck_import", "bcheck_list", "bcheck_remove",
        "scancheck_create_passive", "scancheck_create_active", "scancheck_list", "scancheck_remove"
    )

    private fun buildActivityTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Stats bar
        activityStatsLabel = JLabel("  Calls: 0  |  Errors: 0  |  Events: 0")
        activityStatsLabel.font = Font("Monospaced", Font.PLAIN, 11)
        activityStatsLabel.border = BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY),
            EmptyBorder(4, 8, 4, 8)
        )

        // Filter bar
        val filterBar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 3))
        val group = ButtonGroup()
        for ((label, filter) in listOf("All" to "all", "HTTP" to "http", "Proxy" to "proxy", "Scanner" to "scanner", "Other" to "other")) {
            val btn = JToggleButton(label, filter == "all")
            btn.font = btn.font.deriveFont(11f); btn.margin = Insets(2, 8, 2, 8); btn.isFocusPainted = false
            btn.addActionListener { activityFilter = filter; applyActivityFilter() }
            group.add(btn); filterBar.add(btn)
        }
        filterBar.add(Box.createHorizontalStrut(8))
        filterBar.add(JLabel("Search:"))
        val searchField = JTextField(18)
        searchField.font = Font("Monospaced", Font.PLAIN, 11)
        searchField.addKeyListener(object : java.awt.event.KeyAdapter() {
            override fun keyReleased(e: java.awt.event.KeyEvent?) { activitySearch = searchField.text.trim().lowercase(); applyActivityFilter() }
        })
        filterBar.add(searchField)
        val clearBtn = JButton("Clear"); clearBtn.font = clearBtn.font.deriveFont(11f); clearBtn.margin = Insets(2, 8, 2, 8)
        clearBtn.addActionListener { activityTableModel.rowCount = 0; activityById.clear(); totalToolCalls.set(0); totalErrors.set(0); perToolCounts.clear() }
        filterBar.add(clearBtn)

        val topBar = JPanel(BorderLayout()); topBar.add(activityStatsLabel, BorderLayout.NORTH); topBar.add(filterBar, BorderLayout.SOUTH)

        // Table
        activityTableModel = object : DefaultTableModel(arrayOf("#", "Time", "Tool", "Method", "URL / Detail", "Host", "Status", "ms"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        activityTable = JTable(activityTableModel)
        activityTable.fillsViewportHeight = true; activityTable.rowHeight = 22; activityTable.setShowGrid(false)
        activityTable.intercellSpacing = Dimension(0, 0); activityTable.autoCreateRowSorter = true
        activityTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        val cols = activityTable.columnModel
        cols.getColumn(0).preferredWidth = 40; cols.getColumn(0).maxWidth = 60
        cols.getColumn(1).preferredWidth = 90; cols.getColumn(1).maxWidth = 110
        cols.getColumn(2).preferredWidth = 180; cols.getColumn(2).maxWidth = 250
        cols.getColumn(3).preferredWidth = 55; cols.getColumn(3).maxWidth = 70
        cols.getColumn(4).preferredWidth = 400
        cols.getColumn(5).preferredWidth = 130; cols.getColumn(5).maxWidth = 200
        cols.getColumn(6).preferredWidth = 50; cols.getColumn(6).maxWidth = 65
        cols.getColumn(7).preferredWidth = 50; cols.getColumn(7).maxWidth = 70
        cols.getColumn(2).cellRenderer = ColorRenderer(mapOf("http" to Color(0x58, 0xA6, 0xFF), "proxy" to Color(0x3F, 0xB9, 0x50), "scanner" to Color(0xF8, 0x51, 0x49))) { name ->
            when { name in httpToolNames -> "http"; name in proxyToolNames -> "proxy"; name in scannerToolNames -> "scanner"; else -> "" }
        }
        cols.getColumn(3).cellRenderer = MethodRenderer()
        cols.getColumn(6).cellRenderer = StatusCodeRenderer()

        activityTable.selectionModel.addListSelectionListener { e -> if (!e.valueIsAdjusting) showActivityDetail() }
        activityTable.addMouseListener(ContextMenuListener { row, e -> showActivityContextMenu(row, e) })

        // Detail panel
        activityRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        activityResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
        activityDetailInfo = JTextArea(3, 60)
        activityDetailInfo.isEditable = false; activityDetailInfo.font = Font("Monospaced", Font.PLAIN, 11)
        activityDetailInfo.lineWrap = true; activityDetailInfo.wrapStyleWord = true
        activityDetailInfo.text = "Select an activity row to view details."

        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Info", JScrollPane(activityDetailInfo))
        detailTabs.addTab("Request", activityRequestEditor.uiComponent())
        detailTabs.addTab("Response", activityResponseEditor.uiComponent())

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(activityTable), detailTabs)
        split.resizeWeight = 0.6; split.dividerSize = 5
        panel.add(topBar, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        return panel
    }

    private fun wireActivityListener() {
        stateManager.mcpActivityListeners.add { entry ->
            totalToolCalls.incrementAndGet()
            if (entry.isError) totalErrors.incrementAndGet()
            perToolCounts.computeIfAbsent(entry.toolName) { AtomicLong(0) }.incrementAndGet()
            activityById[entry.id] = entry
            SwingUtilities.invokeLater {
                while (activityTableModel.rowCount >= MAX_TABLE_ROWS) {
                    val oldId = activityTableModel.getValueAt(activityTableModel.rowCount - 1, 0) as? Long
                    if (oldId != null) activityById.remove(oldId)
                    activityTableModel.removeRow(activityTableModel.rowCount - 1)
                }
                if (passesActivityFilter(entry)) addActivityRow(entry, 0)
                updateActivityStats()
            }
        }
    }

    private fun passesActivityFilter(e: McpActivityEntry): Boolean {
        when (activityFilter) {
            "http" -> if (e.toolName !in httpToolNames) return false
            "proxy" -> if (e.toolName !in proxyToolNames) return false
            "scanner" -> if (e.toolName !in scannerToolNames) return false
            "other" -> if (e.toolName in httpToolNames || e.toolName in proxyToolNames || e.toolName in scannerToolNames) return false
        }
        if (activitySearch.isNotEmpty() && activitySearch !in "${e.toolName} ${e.url} ${e.host} ${e.method}".lowercase()) return false
        return true
    }

    private fun addActivityRow(e: McpActivityEntry, at: Int) {
        val time = try { LocalDateTime.ofInstant(Instant.parse(e.timestamp), ZoneId.systemDefault()).format(TIME_FORMAT) } catch (_: Exception) { e.timestamp.takeLast(12) }
        activityTableModel.insertRow(at, arrayOf<Any?>(e.id, time, e.toolName, e.method.ifEmpty { "-" }, e.url.ifEmpty { e.argsSummary.take(120) }, e.host, if (e.statusCode > 0) e.statusCode else null as Int?, e.durationMs.toInt()))
    }

    private fun applyActivityFilter() {
        activityTableModel.rowCount = 0
        for (e in stateManager.mcpActivity.toList()) {
            if (passesActivityFilter(e)) addActivityRow(e, activityTableModel.rowCount)
            if (activityTableModel.rowCount >= MAX_TABLE_ROWS) break
        }
    }

    private fun updateActivityStats() {
        val top = perToolCounts.entries.sortedByDescending { it.value.get() }.take(3).joinToString("  ") { "${it.key}(${it.value.get()})" }
        activityStatsLabel.text = "  Calls: ${totalToolCalls.get()}  |  Errors: ${totalErrors.get()}  |  Events: ${eventBus.size()}  |  Top: $top"
    }

    private fun showActivityDetail() {
        val vr = activityTable.selectedRow; if (vr < 0) return
        val id = activityTableModel.getValueAt(activityTable.convertRowIndexToModel(vr), 0) as? Long ?: return
        val entry = activityById[id] ?: return
        activityDetailInfo.text = "Tool: ${entry.toolName}  |  Duration: ${entry.durationMs}ms  |  Error: ${entry.isError}\nURL: ${entry.url}\nHost: ${entry.host}\n\nArguments:\n${entry.argsSummary}\n\nResult:\n${entry.resultSummary}"
        activityDetailInfo.caretPosition = 0
        entry.requestResponse?.let { rr ->
            try { rr.request()?.let { activityRequestEditor.setRequest(it) } } catch (_: Exception) {}
            try { rr.response()?.let { activityResponseEditor.setResponse(it) } } catch (_: Exception) {}
        }
    }

    private fun showActivityContextMenu(viewRow: Int, e: MouseEvent) {
        val id = activityTableModel.getValueAt(activityTable.convertRowIndexToModel(viewRow), 0) as? Long ?: return
        val entry = activityById[id] ?: return
        val menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater").apply { addActionListener {
            val req = entry.requestResponse?.request() ?: if (entry.url.isNotEmpty()) HttpRequest.httpRequestFromUrl(entry.url) else null
            req?.let { api.repeater().sendToRepeater(it, "MCP-${entry.toolName}") }
        }})
        menu.add(JMenuItem("Send to Intruder").apply { addActionListener {
            val req = entry.requestResponse?.request() ?: if (entry.url.isNotEmpty()) HttpRequest.httpRequestFromUrl(entry.url) else null
            req?.let { api.intruder().sendToIntruder(it, "MCP-${entry.toolName}") }
        }})
        menu.addSeparator()
        if (entry.host.isNotEmpty()) {
            menu.add(JMenuItem("Add '${entry.host}' to Scope").apply { addActionListener {
                try { api.scope().includeInScope("https://${entry.host}") } catch (_: Exception) {}
            }})
        }
        if (entry.url.isNotEmpty()) menu.add(JMenuItem("Copy URL").apply { addActionListener { copyToClipboard(entry.url) } })
        menu.add(JMenuItem("Copy Result JSON").apply { addActionListener { copyToClipboard(entry.resultSummary) } })
        menu.show(e.component, e.x, e.y)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 2: PROXY EXPLORER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var proxyTableModel: DefaultTableModel
    private lateinit var proxyTable: JTable
    private lateinit var proxyRequestEditor: HttpRequestEditor
    private lateinit var proxyResponseEditor: HttpResponseEditor
    private var proxyHistoryCache = mutableListOf<JsonObject>()

    private fun buildProxyTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Controls bar
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        val hostField = JTextField(15); hostField.toolTipText = "Host filter"
        val methodCombo = JComboBox(arrayOf("Any", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"))
        val statusField = JTextField(5); statusField.toolTipText = "Status code"
        val scopeCheck = JCheckBox("In-scope only", false)
        val countField = JTextField("100", 4); countField.toolTipText = "Max results"
        val fetchBtn = JButton("Fetch History")
        val searchField = JTextField(15); searchField.toolTipText = "Regex search"
        val searchBtn = JButton("Search")

        controls.add(JLabel("Host:")); controls.add(hostField)
        controls.add(JLabel("Method:")); controls.add(methodCombo)
        controls.add(JLabel("Status:")); controls.add(statusField)
        controls.add(scopeCheck)
        controls.add(JLabel("Count:")); controls.add(countField)
        controls.add(fetchBtn)
        controls.add(Box.createHorizontalStrut(12))
        controls.add(JLabel("Regex:")); controls.add(searchField); controls.add(searchBtn)

        // Table
        proxyTableModel = object : DefaultTableModel(arrayOf("#", "Method", "URL", "Host", "Status", "MIME", "Length"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        proxyTable = JTable(proxyTableModel)
        proxyTable.fillsViewportHeight = true; proxyTable.rowHeight = 22; proxyTable.setShowGrid(false)
        proxyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        proxyTable.columnModel.getColumn(0).preferredWidth = 50; proxyTable.columnModel.getColumn(0).maxWidth = 70
        proxyTable.columnModel.getColumn(1).preferredWidth = 60; proxyTable.columnModel.getColumn(1).maxWidth = 80
        proxyTable.columnModel.getColumn(2).preferredWidth = 400
        proxyTable.columnModel.getColumn(3).preferredWidth = 140; proxyTable.columnModel.getColumn(3).maxWidth = 200
        proxyTable.columnModel.getColumn(4).preferredWidth = 55; proxyTable.columnModel.getColumn(4).maxWidth = 70
        proxyTable.columnModel.getColumn(5).preferredWidth = 80; proxyTable.columnModel.getColumn(5).maxWidth = 120
        proxyTable.columnModel.getColumn(6).preferredWidth = 70; proxyTable.columnModel.getColumn(6).maxWidth = 100
        proxyTable.columnModel.getColumn(1).cellRenderer = MethodRenderer()
        proxyTable.columnModel.getColumn(4).cellRenderer = StatusCodeRenderer()

        // Detail
        proxyRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        proxyResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)
        val detailTabs = JTabbedPane(JTabbedPane.TOP)
        detailTabs.addTab("Request", proxyRequestEditor.uiComponent())
        detailTabs.addTab("Response", proxyResponseEditor.uiComponent())

        proxyTable.selectionModel.addListSelectionListener { e -> if (!e.valueIsAdjusting) showProxyDetail() }
        proxyTable.addMouseListener(ContextMenuListener { row, ev -> showProxyContextMenu(row, ev) })

        // Fetch action
        proxyFetchButton = fetchBtn
        fetchBtn.addActionListener {
            SwingWorker(api, "Fetching proxy history...") {
                val host = hostField.text.trim().ifEmpty { null }
                val method = if (methodCombo.selectedIndex == 0) null else methodCombo.selectedItem as String
                val status = statusField.text.trim().toIntOrNull()
                val count = countField.text.trim().toIntOrNull() ?: 100
                val result = bridges.proxy.getHistory(0, count, host, method, status, null, scopeCheck.isSelected, true, true, null)
                if (showBridgeError(result, "Fetch proxy history")) return@SwingWorker
                val items = result["items"]?.jsonArray ?: JsonArray(emptyList())
                proxyHistoryCache.clear()
                SwingUtilities.invokeLater {
                    proxyTableModel.rowCount = 0
                    for (item in items) {
                        val obj = item.jsonObject
                        proxyHistoryCache.add(obj)
                        proxyTableModel.addRow(arrayOf<Any?>(
                            obj["index"]?.jsonPrimitive?.intOrNull ?: 0,
                            obj["method"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["url"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["host"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["status_code"]?.jsonPrimitive?.intOrNull as Int?,
                            obj["response_mime_type"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["response_length"]?.jsonPrimitive?.intOrNull ?: 0
                        ))
                    }
                }
            }
        }

        // Search action
        searchBtn.addActionListener {
            val pattern = searchField.text.trim(); if (pattern.isEmpty()) return@addActionListener
            SwingWorker(api, "Searching proxy history...") {
                val result = bridges.proxy.searchHistory(pattern, "both", false, 200, scopeCheck.isSelected, true, true, null)
                val items = result["matches"]?.jsonArray ?: JsonArray(emptyList())
                proxyHistoryCache.clear()
                SwingUtilities.invokeLater {
                    proxyTableModel.rowCount = 0
                    for (item in items) {
                        val obj = item.jsonObject
                        proxyHistoryCache.add(obj)
                        proxyTableModel.addRow(arrayOf<Any?>(
                            obj["index"]?.jsonPrimitive?.intOrNull ?: 0,
                            obj["method"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["url"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["host"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["status_code"]?.jsonPrimitive?.intOrNull as Int?,
                            obj["response_mime_type"]?.jsonPrimitive?.contentOrNull ?: "",
                            obj["response_length"]?.jsonPrimitive?.intOrNull ?: 0
                        ))
                    }
                }
            }
        }

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(proxyTable), detailTabs)
        split.resizeWeight = 0.55; split.dividerSize = 5
        panel.add(controls, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        return panel
    }

    private fun showProxyDetail() {
        val vr = proxyTable.selectedRow; if (vr < 0) return
        val mr = proxyTable.convertRowIndexToModel(vr)
        if (mr >= proxyHistoryCache.size) return
        val item = proxyHistoryCache[mr]
        try {
            val reqStr = item["request"]?.jsonPrimitive?.contentOrNull
            if (reqStr != null) {
                val host = item["host"]?.jsonPrimitive?.contentOrNull ?: ""
                val port = item["port"]?.jsonPrimitive?.intOrNull ?: 443
                val tls = item["is_tls"]?.jsonPrimitive?.booleanOrNull ?: true
                val service = burp.api.montoya.http.HttpService.httpService(host, port, tls)
                proxyRequestEditor.setRequest(HttpRequest.httpRequest(service, reqStr))
            }
        } catch (_: Exception) {}
        try {
            val respStr = item["response"]?.jsonPrimitive?.contentOrNull
            if (respStr != null) proxyResponseEditor.setResponse(HttpResponse.httpResponse(respStr))
        } catch (_: Exception) {}
    }

    private fun showProxyContextMenu(viewRow: Int, e: MouseEvent) {
        val mr = proxyTable.convertRowIndexToModel(viewRow)
        if (mr >= proxyHistoryCache.size) return
        val item = proxyHistoryCache[mr]
        val url = item["url"]?.jsonPrimitive?.contentOrNull ?: ""
        val host = item["host"]?.jsonPrimitive?.contentOrNull ?: ""
        val menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater").apply { addActionListener {
            try {
                val reqStr = item["request"]?.jsonPrimitive?.contentOrNull ?: return@addActionListener
                val service = burp.api.montoya.http.HttpService.httpService(host, item["port"]?.jsonPrimitive?.intOrNull ?: 443, item["is_tls"]?.jsonPrimitive?.booleanOrNull ?: true)
                api.repeater().sendToRepeater(HttpRequest.httpRequest(service, reqStr), "Proxy-$host")
            } catch (_: Exception) {}
        }})
        menu.add(JMenuItem("Send to Intruder").apply { addActionListener {
            try {
                val reqStr = item["request"]?.jsonPrimitive?.contentOrNull ?: return@addActionListener
                val service = burp.api.montoya.http.HttpService.httpService(host, item["port"]?.jsonPrimitive?.intOrNull ?: 443, item["is_tls"]?.jsonPrimitive?.booleanOrNull ?: true)
                api.intruder().sendToIntruder(HttpRequest.httpRequest(service, reqStr))
            } catch (_: Exception) {}
        }})
        menu.addSeparator()
        if (host.isNotEmpty()) menu.add(JMenuItem("Add '$host' to Scope").apply { addActionListener { try { api.scope().includeInScope("https://$host") } catch (_: Exception) {} } })
        if (url.isNotEmpty()) menu.add(JMenuItem("Copy URL").apply { addActionListener { copyToClipboard(url) } })
        menu.show(e.component, e.x, e.y)
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 3: SCANNER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var scannerTableModel: DefaultTableModel
    private lateinit var scannerDetailArea: JTextArea

    private fun buildScannerTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))

        // Controls
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        val urlField = JTextField(20); urlField.toolTipText = "URL prefix filter"
        val sevCombo = JComboBox(arrayOf("Any", "HIGH", "MEDIUM", "LOW", "INFORMATION"))
        val confCombo = JComboBox(arrayOf("Any", "CERTAIN", "FIRM", "TENTATIVE"))
        val fetchBtn = JButton("Fetch Issues")
        val countLabel = JLabel("Issues: 0")
        controls.add(JLabel("URL prefix:")); controls.add(urlField)
        controls.add(JLabel("Severity:")); controls.add(sevCombo)
        controls.add(JLabel("Confidence:")); controls.add(confCombo)
        controls.add(fetchBtn); controls.add(Box.createHorizontalStrut(16)); controls.add(countLabel)

        // Table
        scannerTableModel = object : DefaultTableModel(arrayOf("Severity", "Confidence", "Name", "URL", "Host"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        val scannerTable = JTable(scannerTableModel)
        scannerTable.fillsViewportHeight = true; scannerTable.rowHeight = 22; scannerTable.setShowGrid(false)
        scannerTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        scannerTable.columnModel.getColumn(0).preferredWidth = 80; scannerTable.columnModel.getColumn(0).maxWidth = 120
        scannerTable.columnModel.getColumn(1).preferredWidth = 80; scannerTable.columnModel.getColumn(1).maxWidth = 120
        scannerTable.columnModel.getColumn(2).preferredWidth = 250
        scannerTable.columnModel.getColumn(3).preferredWidth = 350
        scannerTable.columnModel.getColumn(4).preferredWidth = 150
        scannerTable.columnModel.getColumn(0).cellRenderer = SeverityRenderer()

        // Detail
        scannerDetailArea = JTextArea(8, 60)
        scannerDetailArea.isEditable = false; scannerDetailArea.font = Font("Monospaced", Font.PLAIN, 11)
        scannerDetailArea.lineWrap = true; scannerDetailArea.wrapStyleWord = true
        scannerDetailArea.text = "Click 'Fetch Issues' to load scanner findings."

        var issuesCache = listOf<JsonObject>()
        scannerTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) {
                val vr = scannerTable.selectedRow; if (vr < 0) return@addListSelectionListener
                val mr = scannerTable.convertRowIndexToModel(vr)
                if (mr < issuesCache.size) {
                    val issue = issuesCache[mr]
                    val sb = StringBuilder()
                    sb.appendLine("Name: ${issue["name"]?.jsonPrimitive?.contentOrNull ?: ""}")
                    sb.appendLine("Severity: ${issue["severity"]?.jsonPrimitive?.contentOrNull ?: ""}")
                    sb.appendLine("Confidence: ${issue["confidence"]?.jsonPrimitive?.contentOrNull ?: ""}")
                    sb.appendLine("URL: ${issue["url"]?.jsonPrimitive?.contentOrNull ?: ""}")
                    sb.appendLine()
                    sb.appendLine("Detail:")
                    sb.appendLine(issue["detail"]?.jsonPrimitive?.contentOrNull ?: "(none)")
                    sb.appendLine()
                    sb.appendLine("Remediation:")
                    sb.appendLine(issue["remediation"]?.jsonPrimitive?.contentOrNull ?: "(none)")
                    scannerDetailArea.text = sb.toString()
                    scannerDetailArea.caretPosition = 0
                }
            }
        }

        scannerFetchButton = fetchBtn
        fetchBtn.addActionListener {
            SwingWorker(api, "Fetching scanner issues...") {
                val urlPrefix = urlField.text.trim().ifEmpty { null }
                val sev = if (sevCombo.selectedIndex == 0) null else (sevCombo.selectedItem as String).lowercase()
                val conf = if (confCombo.selectedIndex == 0) null else (confCombo.selectedItem as String).lowercase()
                val result = bridges.scanner.getAllIssues(urlPrefix, sev, conf, 500)
                if (showBridgeError(result, "Fetch scanner issues")) return@SwingWorker
                val items = result["issues"]?.jsonArray ?: JsonArray(emptyList())
                issuesCache = items.map { it.jsonObject }
                SwingUtilities.invokeLater {
                    scannerTableModel.rowCount = 0
                    for (issue in issuesCache) {
                        scannerTableModel.addRow(arrayOf(
                            issue["severity"]?.jsonPrimitive?.contentOrNull ?: "",
                            issue["confidence"]?.jsonPrimitive?.contentOrNull ?: "",
                            issue["name"]?.jsonPrimitive?.contentOrNull ?: "",
                            issue["url"]?.jsonPrimitive?.contentOrNull ?: "",
                            issue["host"]?.jsonPrimitive?.contentOrNull ?: ""
                        ))
                    }
                    countLabel.text = "Issues: ${issuesCache.size}"
                }
            }
        }

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(scannerTable), JScrollPane(scannerDetailArea))
        split.resizeWeight = 0.6; split.dividerSize = 5
        panel.add(controls, BorderLayout.NORTH); panel.add(split, BorderLayout.CENTER)
        return panel
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 4: COLLABORATOR
    // ═══════════════════════════════════════════════════════════════════════

    private fun buildCollaboratorTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 4))
        panel.border = EmptyBorder(8, 8, 8, 8)

        // Top: create client + generate payload
        val topPanel = JPanel(GridBagLayout())
        topPanel.border = BorderFactory.createTitledBorder("Collaborator Client")
        val gbc = GridBagConstraints().apply { insets = Insets(4, 6, 4, 6); anchor = GridBagConstraints.WEST }

        val clientIdField = JTextField(30); clientIdField.isEditable = false
        val serverField = JTextField(30); serverField.isEditable = false
        val payloadField = JTextField(40); payloadField.isEditable = false
        val createBtn = JButton("Create Client")
        val generateBtn = JButton("Generate Payload"); generateBtn.isEnabled = false
        val pollBtn = JButton("Poll Interactions"); pollBtn.isEnabled = false
        val copyPayloadBtn = JButton("Copy Payload"); copyPayloadBtn.isEnabled = false

        gbc.gridy = 0; gbc.gridx = 0; topPanel.add(JLabel("Client ID:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; topPanel.add(clientIdField, gbc)
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0; topPanel.add(createBtn, gbc)
        gbc.gridy = 1; gbc.gridx = 0; topPanel.add(JLabel("Server:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; topPanel.add(serverField, gbc)
        gbc.gridy = 2; gbc.gridx = 0; topPanel.add(JLabel("Payload:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; topPanel.add(payloadField, gbc)
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        val payloadBtnPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        payloadBtnPanel.add(generateBtn); payloadBtnPanel.add(copyPayloadBtn); payloadBtnPanel.add(pollBtn)
        topPanel.add(payloadBtnPanel, gbc)

        // Bottom: interactions table
        val interTableModel = object : DefaultTableModel(arrayOf("Type", "Client IP", "Timestamp", "Payload ID", "Details"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
        }
        val interTable = JTable(interTableModel)
        interTable.fillsViewportHeight = true; interTable.rowHeight = 22; interTable.setShowGrid(false)
        interTable.columnModel.getColumn(0).preferredWidth = 60; interTable.columnModel.getColumn(0).maxWidth = 80
        interTable.columnModel.getColumn(1).preferredWidth = 130; interTable.columnModel.getColumn(1).maxWidth = 180
        interTable.columnModel.getColumn(2).preferredWidth = 160
        interTable.columnModel.getColumn(3).preferredWidth = 120
        interTable.columnModel.getColumn(4).preferredWidth = 350
        val interScroll = JScrollPane(interTable)
        interScroll.border = BorderFactory.createTitledBorder("Interactions")

        // Maps a serialized interaction (the shape produced by
        // CollaboratorBridge.serializeInteraction) to a table row. The bridge
        // emits `id` + type-specific `*_details` objects — NOT the flat
        // `payload_id`/`details`/`raw_query` keys the old code looked for, which
        // is why the Payload ID and Details columns were always blank.
        fun interactionRow(obj: JsonObject): Array<Any?> {
            val type = obj["type"]?.jsonPrimitive?.contentOrNull ?: ""
            val details = when (type) {
                "dns" -> obj["dns_details"]?.jsonObject?.let {
                    "${it["query_type"]?.jsonPrimitive?.contentOrNull ?: ""} ${it["query_name"]?.jsonPrimitive?.contentOrNull ?: ""}".trim()
                }
                "http" -> obj["http_details"]?.jsonObject?.let {
                    "${it["request_method"]?.jsonPrimitive?.contentOrNull ?: ""} ${it["request_url"]?.jsonPrimitive?.contentOrNull ?: ""} (${it["response_status"]?.jsonPrimitive?.contentOrNull ?: "?"})".trim()
                }
                "smtp" -> obj["smtp_details"]?.jsonObject?.get("conversation")?.jsonPrimitive?.contentOrNull
                else -> null
            } ?: ""
            return arrayOf(
                type,
                obj["client_ip"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["timestamp"]?.jsonPrimitive?.contentOrNull ?: "",
                obj["id"]?.jsonPrimitive?.contentOrNull ?: "",
                details
            )
        }

        // Dedup by interaction id so a hit observed by both a manual poll and
        // the MCP-driven poll (which also emits collaborator.interaction events)
        // is only listed once.
        val seenInteractions = java.util.Collections.synchronizedSet(HashSet<String>())
        fun addInteraction(obj: JsonObject) {
            val id = obj["id"]?.jsonPrimitive?.contentOrNull ?: ""
            if (id.isNotEmpty() && !seenInteractions.add(id)) return
            val row = interactionRow(obj)
            SwingUtilities.invokeLater { interTableModel.addRow(row) }
        }

        // Reflect agent/MCP-driven collaborator activity live. CollaboratorBridge
        // emits one collaborator.interaction event per hit on every poll — from
        // an MCP tool call OR this panel's Poll button — so the table now fills
        // even when the operator never touched these controls.
        eventBus.subscribe(listOf("collaborator.interaction")) { event ->
            addInteraction(event.data)
        }

        var currentClientId = ""

        createBtn.addActionListener {
            SwingWorker(api, "Creating collaborator client...") {
                val result = bridges.collaborator.createClient()
                if (showBridgeError(result, "Create collaborator client")) return@SwingWorker
                val cid = result["client_id"]?.jsonPrimitive?.contentOrNull ?: ""
                val server = result["server"]?.jsonPrimitive?.contentOrNull ?: ""
                currentClientId = cid
                SwingUtilities.invokeLater {
                    clientIdField.text = cid; serverField.text = server
                    generateBtn.isEnabled = cid.isNotEmpty(); pollBtn.isEnabled = cid.isNotEmpty()
                }
            }
        }

        generateBtn.addActionListener {
            if (currentClientId.isEmpty()) return@addActionListener
            SwingWorker(api, "Generating payload...") {
                val result = bridges.collaborator.generatePayload(currentClientId, null)
                val payload = result["payload"]?.jsonPrimitive?.contentOrNull ?: ""
                SwingUtilities.invokeLater {
                    payloadField.text = payload; copyPayloadBtn.isEnabled = payload.isNotEmpty()
                }
            }
        }

        copyPayloadBtn.addActionListener { copyToClipboard(payloadField.text) }

        pollBtn.addActionListener {
            if (currentClientId.isEmpty()) return@addActionListener
            SwingWorker(api, "Polling interactions...") {
                val result = bridges.collaborator.pollInteractions(currentClientId, null, null)
                if (showBridgeError(result, "Poll interactions")) return@SwingWorker
                // pollInteractions already emits collaborator.interaction events
                // that the subscription above renders (deduped). Route the direct
                // results through the same path so manual polls of THIS panel's
                // client also appear, regardless of event timing.
                val interactions = result["interactions"]?.jsonArray ?: JsonArray(emptyList())
                interactions.forEach { addInteraction(it.jsonObject) }
            }
        }

        panel.add(topPanel, BorderLayout.NORTH); panel.add(interScroll, BorderLayout.CENTER)
        return panel
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 5: RULES MANAGER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var proxyRulesModel: DefaultTableModel
    private lateinit var trafficRulesModel: DefaultTableModel
    private lateinit var sessionRulesModel: DefaultTableModel

    private fun buildRulesTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))
        panel.border = EmptyBorder(8, 8, 8, 8)

        val rulesTabbed = JTabbedPane(JTabbedPane.TOP)

        // Proxy Rules
        proxyRulesModel = object : DefaultTableModel(arrayOf("ID", "Type", "Action", "Match Host", "Match URL", "Match Method", "Enabled"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
            override fun getColumnClass(c: Int) = if (c == 6) java.lang.Boolean::class.java else String::class.java
        }
        val proxyRulesTable = JTable(proxyRulesModel)
        proxyRulesTable.fillsViewportHeight = true; proxyRulesTable.rowHeight = 22
        proxyRulesTable.addMouseListener(ContextMenuListener { row, e ->
            val menu = JPopupMenu()
            val ruleId = proxyRulesModel.getValueAt(row, 0)?.toString() ?: return@ContextMenuListener
            menu.add(JMenuItem("Toggle Enable/Disable").apply { addActionListener {
                val rule = stateManager.proxyRules.find { it.ruleId == ruleId }
                if (rule != null) { rule.enabled = !rule.enabled; refreshRulesTab() }
            }})
            menu.add(JMenuItem("Delete Rule").apply { addActionListener {
                stateManager.proxyRules.removeIf { it.ruleId == ruleId }; refreshRulesTab()
            }})
            menu.show(e.component, e.x, e.y)
        })
        rulesTabbed.addTab("Proxy Rules (${stateManager.proxyRules.size})", JScrollPane(proxyRulesTable))

        // Traffic Rules
        trafficRulesModel = object : DefaultTableModel(arrayOf("ID", "Direction", "Match URL", "Match Host", "Add Header", "Enabled"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
            override fun getColumnClass(c: Int) = if (c == 5) java.lang.Boolean::class.java else String::class.java
        }
        val trafficRulesTable = JTable(trafficRulesModel)
        trafficRulesTable.fillsViewportHeight = true; trafficRulesTable.rowHeight = 22
        trafficRulesTable.addMouseListener(ContextMenuListener { row, e ->
            val menu = JPopupMenu()
            val ruleId = trafficRulesModel.getValueAt(row, 0)?.toString() ?: return@ContextMenuListener
            menu.add(JMenuItem("Toggle Enable/Disable").apply { addActionListener {
                val rule = stateManager.trafficRules.find { it.ruleId == ruleId }
                if (rule != null) { rule.enabled = !rule.enabled; refreshRulesTab() }
            }})
            menu.add(JMenuItem("Delete Rule").apply { addActionListener {
                stateManager.trafficRules.removeIf { it.ruleId == ruleId }; refreshRulesTab()
            }})
            menu.show(e.component, e.x, e.y)
        })
        rulesTabbed.addTab("Traffic Rules (${stateManager.trafficRules.size})", JScrollPane(trafficRulesTable))

        // Session Rules
        sessionRulesModel = object : DefaultTableModel(arrayOf("Name", "Scope", "Extract From", "Inject Into", "Last Value", "Enabled"), 0) {
            override fun isCellEditable(r: Int, c: Int) = false
            override fun getColumnClass(c: Int) = if (c == 5) java.lang.Boolean::class.java else String::class.java
        }
        val sessionRulesTable = JTable(sessionRulesModel)
        sessionRulesTable.fillsViewportHeight = true; sessionRulesTable.rowHeight = 22
        rulesTabbed.addTab("Session Rules (${stateManager.sessionRules.size})", JScrollPane(sessionRulesTable))

        val refreshBtn = JButton("Refresh")
        refreshBtn.addActionListener { refreshRulesTab() }
        val btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT)); btnPanel.add(refreshBtn)

        panel.add(btnPanel, BorderLayout.NORTH); panel.add(rulesTabbed, BorderLayout.CENTER)
        refreshRulesTab()
        return panel
    }

    private fun refreshRulesTab() {
        SwingUtilities.invokeLater {
            // Proxy rules
            proxyRulesModel.rowCount = 0
            for (r in stateManager.proxyRules) {
                proxyRulesModel.addRow(arrayOf<Any?>(r.ruleId, r.type, r.action, r.matchHost ?: "*", r.matchUrl ?: "*", r.matchMethod ?: "*", r.enabled))
            }
            // Traffic rules
            trafficRulesModel.rowCount = 0
            for (r in stateManager.trafficRules) {
                trafficRulesModel.addRow(arrayOf<Any?>(r.ruleId, r.direction, r.matchUrl ?: "*", r.matchHost ?: "*", r.modifyAddHeader ?: "", r.enabled))
            }
            // Session rules
            sessionRulesModel.rowCount = 0
            for (r in stateManager.sessionRules) {
                sessionRulesModel.addRow(arrayOf<Any?>(r.ruleName, r.scope, r.extractFrom, r.injectInto, r.lastExtractedValue ?: "(none)", r.enabled))
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  TAB 6: SERVER
    // ═══════════════════════════════════════════════════════════════════════

    private lateinit var serverUptimeLabel: JLabel
    private lateinit var serverEventsLabel: JLabel
    private lateinit var serverToolCallsLabel: JLabel
    private lateinit var serverWsLabel: JLabel
    private lateinit var serverCollabLabel: JLabel
    private lateinit var serverScanLabel: JLabel

    private fun buildServerTab(): JPanel {
        val panel = JPanel(BorderLayout(0, 0))
        panel.border = EmptyBorder(12, 12, 12, 12)

        val content = JPanel(GridBagLayout())
        val gbc = GridBagConstraints().apply { insets = Insets(4, 8, 4, 8); anchor = GridBagConstraints.WEST; fill = GridBagConstraints.HORIZONTAL }

        fun addRow(row: Int, label: String, valueLabel: JLabel) {
            gbc.gridy = row; gbc.gridx = 0; gbc.weightx = 0.0; content.add(JLabel(label).apply { font = font.deriveFont(Font.BOLD) }, gbc)
            gbc.gridx = 1; gbc.weightx = 1.0; valueLabel.font = Font("Monospaced", Font.PLAIN, 12); content.add(valueLabel, gbc)
        }

        // Connection info
        gbc.gridy = 0; gbc.gridx = 0; gbc.gridwidth = 2; gbc.weightx = 1.0
        content.add(JLabel("Connection Information").apply { font = font.deriveFont(Font.BOLD, 14f) }, gbc)
        gbc.gridwidth = 1

        addRow(1, "MCP SSE (root /):", JLabel(ConnectionInfo.primarySseUrlForHost(bindHost)))
        addRow(2, "SSE (secondary):", JLabel(ConnectionInfo.secondarySseUrlForHost(bindHost)))
        addRow(3, "Dashboard:", JLabel(ConnectionInfo.dashboardUrlForHost(bindHost)))

        gbc.gridy = 4; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(JSeparator(), gbc); gbc.gridwidth = 1

        // Bind host config. The embedded servers are started before the UI is
        // constructed, so changing this value takes effect on extension reload.
        gbc.gridy = 5; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(JLabel("Server Bind Address").apply { font = font.deriveFont(Font.BOLD, 14f) }, gbc)
        gbc.gridwidth = 1

        gbc.gridy = 6; gbc.gridx = 0; gbc.weightx = 0.0
        content.add(JLabel("Bind host:").apply { font = font.deriveFont(Font.BOLD) }, gbc)
        val bindHostField = JTextField(bindHost, 18)
        bindHostField.font = Font("Monospaced", Font.PLAIN, 12)
        gbc.gridx = 1; gbc.weightx = 1.0
        content.add(bindHostField, gbc)

        val saveBindHostBtn = JButton("Save Bind Address")
        saveBindHostBtn.addActionListener {
            val value = bindHostField.text.trim().ifEmpty { "127.0.0.1" }
            api.persistence().preferences().setString("mcp_bind_host", value)
            JOptionPane.showMessageDialog(
                panel,
                "Bind address saved as $value.\nReload the BurpMCP-Ultra extension for it to take effect.",
                "BurpMCP-Ultra",
                JOptionPane.INFORMATION_MESSAGE
            )
        }
        gbc.gridy = 7; gbc.gridx = 1; gbc.weightx = 0.0
        content.add(saveBindHostBtn, gbc)

        gbc.gridy = 8; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(JSeparator(), gbc); gbc.gridwidth = 1

        // MCP config
        gbc.gridy = 9; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(JLabel("MCP Client Config").apply { font = font.deriveFont(Font.BOLD, 14f) }, gbc)
        gbc.gridwidth = 1

        val configArea = JTextArea(ConnectionInfo.clientConfigJson(authToken, host = bindHost))
        configArea.isEditable = false; configArea.font = Font("Monospaced", Font.PLAIN, 11)
        configArea.lineWrap = true; configArea.wrapStyleWord = false; configArea.rows = 3
        gbc.gridy = 10; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(configArea, gbc)
        val copyConfigBtn = JButton("Copy Config")
        copyConfigBtn.addActionListener { copyToClipboard(configArea.text) }
        gbc.gridy = 11; gbc.gridx = 0; gbc.gridwidth = 1; gbc.weightx = 0.0
        content.add(copyConfigBtn, gbc)
        gbc.gridwidth = 1

        gbc.gridy = 12; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(JSeparator(), gbc); gbc.gridwidth = 1

        // Live stats
        gbc.gridy = 13; gbc.gridx = 0; gbc.gridwidth = 2
        content.add(JLabel("Live Statistics").apply { font = font.deriveFont(Font.BOLD, 14f) }, gbc)
        gbc.gridwidth = 1

        serverUptimeLabel = JLabel("00:00:00"); addRow(14, "Uptime:", serverUptimeLabel)
        serverToolCallsLabel = JLabel("0"); addRow(15, "Total MCP Tool Calls:", serverToolCallsLabel)
        serverEventsLabel = JLabel("0"); addRow(16, "Event Buffer:", serverEventsLabel)
        serverWsLabel = JLabel("0"); addRow(17, "WebSocket Connections:", serverWsLabel)
        serverCollabLabel = JLabel("0"); addRow(18, "Collaborator Clients:", serverCollabLabel)
        serverScanLabel = JLabel("0"); addRow(19, "Active Scan Tasks:", serverScanLabel)

        // Filler
        gbc.gridy = 20; gbc.gridx = 0; gbc.weighty = 1.0; gbc.gridwidth = 2
        content.add(JLabel(), gbc)

        panel.add(JScrollPane(content), BorderLayout.CENTER)
        return panel
    }

    private fun refreshServerTab() {
        SwingUtilities.invokeLater {
            val elapsed = System.currentTimeMillis() - serverStartTime
            val h = elapsed / 3600000; val m = (elapsed % 3600000) / 60000; val s = (elapsed % 60000) / 1000
            serverUptimeLabel.text = String.format("%02d:%02d:%02d", h, m, s)
            serverToolCallsLabel.text = NUMBER_FORMAT.format(totalToolCalls.get())
            serverEventsLabel.text = "${eventBus.size()} events buffered"
            serverWsLabel.text = "${stateManager.websocketConnections.size} active"
            serverCollabLabel.text = "${stateManager.collaboratorClients.size} active"
            serverScanLabel.text = "${stateManager.scanTasks.size} active"
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SHARED UTILITIES
    // ═══════════════════════════════════════════════════════════════════════

    private fun copyToClipboard(text: String) {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }


    /** Runs a block on a background thread, catching errors. */
    private fun SwingWorker(api: MontoyaApi, desc: String, block: () -> Unit) {
        Thread {
            try { block() } catch (e: Exception) {
                api.logging().logToError("BurpMCP-Ultra UI: $desc failed: ${e.message}")
                // Surface the failure to the user instead of silently leaving an
                // empty table — "errored" must not look identical to "no data".
                SwingUtilities.invokeLater {
                    JOptionPane.showMessageDialog(
                        mainPanel, "${e.message ?: e.javaClass.simpleName}",
                        desc.removeSuffix("..."), JOptionPane.WARNING_MESSAGE
                    )
                }
            }
        }.apply { isDaemon = true; name = "BurpMCP-Ultra-UI"; start() }
    }

    /**
     * Bridges return `{"error": "..."}` instead of throwing. If [result] carries
     * an error, surface it (dialog + Burp error log) and return true so the caller
     * can bail — otherwise a failed fetch clears the table to 0 rows and looks
     * indistinguishable from a genuinely empty result.
     */
    private fun showBridgeError(result: JsonObject, context: String): Boolean {
        val err = result["error"]?.jsonPrimitive?.contentOrNull ?: return false
        api.logging().logToError("BurpMCP-Ultra UI: $context: $err")
        SwingUtilities.invokeLater {
            JOptionPane.showMessageDialog(mainPanel, err, "$context failed", JOptionPane.WARNING_MESSAGE)
        }
        return true
    }

    // ── Shared Renderers ───────────────────────────────────────────────────

    private class CircleIcon(private val color: Color, private val d: Int) : Icon {
        override fun paintIcon(c: Component?, g: Graphics, x: Int, y: Int) {
            val g2 = g.create() as Graphics2D
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = color; g2.fillOval(x, y, d, d); g2.dispose()
        }
        override fun getIconWidth() = d; override fun getIconHeight() = d
    }

    private class MethodRenderer : DefaultTableCellRenderer() {
        init { horizontalAlignment = CENTER }
        override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
            val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
            if (!s) foreground = when (v?.toString()) {
                "GET" -> Color(0x3F, 0xB9, 0x50); "POST" -> Color(0x58, 0xA6, 0xFF)
                "PUT" -> Color(0xD2, 0x99, 0x22); "DELETE" -> Color(0xF8, 0x51, 0x49)
                "PATCH" -> Color(0xBC, 0x8C, 0xFF); else -> Color.GRAY
            }
            return comp
        }
    }

    private class StatusCodeRenderer : DefaultTableCellRenderer() {
        init { horizontalAlignment = CENTER }
        override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
            val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
            if (!s && v != null) {
                val code = (v as? Int) ?: 0
                foreground = when { code in 200..299 -> Color(0x3F, 0xB9, 0x50); code in 300..399 -> Color(0x58, 0xA6, 0xFF); code in 400..499 -> Color(0xD2, 0x99, 0x22); code >= 500 -> Color(0xF8, 0x51, 0x49); else -> Color.GRAY }
            }
            return comp
        }
    }

    private class SeverityRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
            val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
            if (!s) foreground = when (v?.toString()?.uppercase()) {
                "HIGH" -> Color(0xF8, 0x51, 0x49); "MEDIUM" -> Color(0xD2, 0x99, 0x22)
                "LOW" -> Color(0x58, 0xA6, 0xFF); "INFORMATION" -> Color.GRAY
                else -> t.foreground
            }
            font = font.deriveFont(Font.BOLD)
            return comp
        }
    }

    /** Generic renderer that maps cell value to a color category via a classifier function. */
    private class ColorRenderer(private val colors: Map<String, Color>, private val classifier: (String) -> String) : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
            val comp = super.getTableCellRendererComponent(t, v, s, f, r, c)
            if (!s) foreground = colors[classifier(v?.toString() ?: "")] ?: t.foreground
            return comp
        }
    }

    /** Reusable right-click mouse listener. */
    private class ContextMenuListener(private val handler: (Int, MouseEvent) -> Unit) : MouseAdapter() {
        override fun mousePressed(e: MouseEvent) = check(e)
        override fun mouseReleased(e: MouseEvent) = check(e)
        private fun check(e: MouseEvent) {
            if (e.isPopupTrigger) {
                val table = e.component as JTable
                val row = table.rowAtPoint(e.point)
                if (row >= 0) { table.setRowSelectionInterval(row, row); handler(row, e) }
            }
        }
    }
}
