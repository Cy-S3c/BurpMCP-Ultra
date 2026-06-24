package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.AuditIssueHandler
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.ScanTask
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.Base64

/**
 * Bridge wrapping the Montoya Scanner API (Pro only).
 *
 * All methods guard against [UnsupportedOperationException] thrown when
 * running on Burp Suite Community Edition, returning meaningful error
 * JSON instead of crashing.
 */
class ScannerBridge(
    private val api: MontoyaApi,
    private val eventBus: EventBus,
    private val stateManager: StateManager
) {

    /**
     * Starts a crawl task against the given URLs.
     *
     * @param urls Seed URLs for the crawler.
     * @param maxDepth Optional maximum crawl depth.
     * @param inScopeOnly Whether to restrict the crawl to in-scope URLs.
     * @return JSON object with the task ID and status.
     */
    fun startCrawl(urls: List<String>, maxDepth: Int?, inScopeOnly: Boolean): JsonObject {
        val crawlTask: Crawl
        try {
            val crawlConfig = CrawlConfiguration.crawlConfiguration(*urls.toTypedArray())
            crawlTask = api.scanner().startCrawl(crawlConfig)
        } catch (e: UnsupportedOperationException) {
            return buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            return buildJsonObject {
                put("error", "Failed to start crawl: ${e.message}")
            }
        }

        val taskId = stateManager.generateId("scan")
        stateManager.scanTasks[taskId] = ScanTask(
            taskId = taskId,
            type = "crawl",
            taskObject = crawlTask,
            createdAt = Instant.now().toString()
        )

        val statusMsg = try { crawlTask.statusMessage() } catch (_: Exception) { "started" }

        return buildJsonObject {
            put("task_id", taskId)
            put("type", "crawl")
            put("status", statusMsg)
            put("urls", buildJsonArray { urls.forEach { add(it) } })
            put("in_scope_only", inScopeOnly)
            put("created_at", stateManager.scanTasks[taskId]!!.createdAt)
        }
    }

    /**
     * Starts an audit task.
     *
     * @param urls Target URLs to audit.
     * @param requests Optional base64-encoded HTTP requests to audit directly.
     * @param auditMode Audit mode: "light", "normal", "thorough". Defaults to "normal".
     * @param crawlFirst Whether to crawl before auditing.
     * @param insertionPointTypes Optional list of insertion point types to test.
     * @return JSON object with task ID and status.
     */
    fun startAudit(
        urls: List<String>?,
        requests: List<String>?,
        auditMode: String?,
        crawlFirst: Boolean,
        insertionPointTypes: List<String>?,
        authHeaderName: String? = null,
        authHeaderValue: String? = null
    ): JsonObject {
        try {
            // If auth header provided, create a traffic rule to inject it
            var authRuleId: String? = null
            if (authHeaderName != null && authHeaderValue != null) {
                authRuleId = stateManager.generateId("auth-rule")
                stateManager.trafficRules.add(com.burpmcp.ultra.state.TrafficRule(
                    ruleId = authRuleId,
                    direction = "request",
                    matchUrl = null,
                    matchHost = null,
                    matchHeader = null,
                    modifyAddHeader = "$authHeaderName: $authHeaderValue",
                    modifyRemoveHeader = null,
                    modifyReplaceHeader = null,
                    enabled = true
                ))
            }

            val builtInConfig = when (auditMode?.lowercase()) {
                "light" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                "thorough" -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                else -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            }
            val auditConfig = AuditConfiguration.auditConfiguration(builtInConfig)

            val auditTask: Audit = api.scanner().startAudit(auditConfig)

            // If raw requests are provided, add them to the audit task
            requests?.forEach { reqBase64 ->
                try {
                    val decoded = Base64.getDecoder().decode(reqBase64)
                    val httpRequest = HttpRequest.httpRequest(BurpByteArray.byteArray(*decoded))
                    auditTask.addRequest(httpRequest)
                } catch (_: Exception) {
                    // Skip malformed requests
                }
            }

            val taskId = stateManager.generateId("scan")
            val scanTask = ScanTask(
                taskId = taskId,
                type = "audit",
                taskObject = auditTask,
                createdAt = Instant.now().toString()
            )
            stateManager.scanTasks[taskId] = scanTask

            val statusMsg = try { auditTask.statusMessage() } catch (_: Exception) { "started" }

            return buildJsonObject {
                put("task_id", taskId)
                put("type", "audit")
                put("status", statusMsg)
                put("audit_mode", auditMode ?: "normal")
                put("crawl_first", crawlFirst)
                put("created_at", scanTask.createdAt)
                if (authRuleId != null) {
                    put("auth_rule_id", authRuleId)
                    put("auth_note", "Traffic rule '$authRuleId' injects auth header. Use http_remove_traffic_rule to remove it when done.")
                }
            }
        } catch (e: UnsupportedOperationException) {
            return buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            return buildJsonObject {
                put("error", "Failed to start audit: ${e.message}")
            }
        }
    }

    /**
     * Returns the current status of a scan task.
     *
     * @param taskId The task identifier.
     * @return JSON object with status, request count, and error count.
     */
    fun getTaskStatus(taskId: String): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        val task = scanTask.taskObject
        val statusMsg = safeStatusMessage(task)
        val reqCount = safeRequestCount(task)
        val errCount = try { when (task) { is Crawl -> task.errorCount(); is Audit -> task.errorCount(); else -> -1 } } catch (_: Throwable) { -1 }
        val issueCount = try { if (task is Audit) task.issues().size else 0 } catch (_: Throwable) { -1 }

        return buildJsonObject {
            put("task_id", taskId)
            put("type", scanTask.type)
            put("status", statusMsg)
            if (reqCount >= 0) put("request_count", reqCount)
            if (errCount >= 0) put("error_count", errCount)
            if (task is Audit && issueCount >= 0) put("issue_count", issueCount)
            put("created_at", scanTask.createdAt)
        }
    }

    /**
     * Lists all scan tasks, optionally filtered by status substring.
     *
     * @param status Optional status filter (case-insensitive substring match).
     * @return JSON array of task status objects.
     */
    fun listTasks(status: String?): JsonArray {
        // Pre-extract all task data outside the JSON builder to ensure
        // exceptions from unimplemented Montoya methods are caught cleanly.
        data class TaskEntry(val id: String, val type: String, val statusMsg: String, val reqCount: Int, val createdAt: String)

        val entries = stateManager.scanTasks.values.map { scanTask ->
            val msg = safeStatusMessage(scanTask.taskObject)
            val cnt = safeRequestCount(scanTask.taskObject)
            TaskEntry(scanTask.taskId, scanTask.type, msg, cnt, scanTask.createdAt)
        }

        return buildJsonArray {
            entries.filter { status == null || it.statusMsg.contains(status, ignoreCase = true) }
                .forEach { entry ->
                    add(buildJsonObject {
                        put("task_id", entry.id)
                        put("type", entry.type)
                        put("status", entry.statusMsg)
                        if (entry.reqCount >= 0) put("request_count", entry.reqCount)
                        put("created_at", entry.createdAt)
                    })
                }
        }
    }

    /** Safely get status message — Burp 2026.1.5 throws "Not yet implemented". */
    private fun safeStatusMessage(task: Any): String {
        return try {
            when (task) {
                is Crawl -> task.statusMessage()
                is Audit -> task.statusMessage()
                else -> "unknown"
            }
        } catch (_: Throwable) { "running" }
    }

    /** Safely get request count — may throw on some Burp versions. */
    private fun safeRequestCount(task: Any): Int {
        return try {
            when (task) {
                is Crawl -> task.requestCount()
                is Audit -> task.requestCount()
                else -> -1
            }
        } catch (_: Throwable) { -1 }
    }

    /**
     * Deletes (cancels) a scan task and removes it from state.
     *
     * @param taskId The task identifier.
     * @return JSON object confirming deletion or reporting an error.
     */
    fun deleteTask(taskId: String): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        return try {
            when (val task = scanTask.taskObject) {
                is Crawl -> task.delete()
                is Audit -> task.delete()
            }
            stateManager.scanTasks.remove(taskId)
            buildJsonObject {
                put("task_id", taskId)
                put("deleted", true)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("task_id", taskId)
                put("error", "Failed to delete task: ${e.message}")
            }
        }
    }

    /**
     * Adds an HTTP request to an existing audit task.
     *
     * @param taskId The audit task identifier.
     * @param request Base64-encoded HTTP request.
     * @param host Target host.
     * @param port Target port.
     * @param useTls Whether to use TLS.
     * @return JSON object confirming the request was added.
     */
    fun addRequestToTask(
        taskId: String,
        request: String,
        host: String?,
        port: Int?,
        useTls: Boolean?
    ): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        val task = scanTask.taskObject
        if (task !is Audit) {
            return buildJsonObject { put("error", "Task $taskId is not an audit task") }
        }

        return try {
            val decoded = Base64.getDecoder().decode(request)
            var httpRequest = HttpRequest.httpRequest(BurpByteArray.byteArray(*decoded))

            if (host != null) {
                val service = HttpService.httpService(
                    host,
                    port ?: if (useTls == true) 443 else 80,
                    useTls ?: false
                )
                httpRequest = httpRequest.withService(service)
            }

            task.addRequest(httpRequest)

            buildJsonObject {
                put("task_id", taskId)
                put("request_added", true)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to add request: ${e.message}")
            }
        }
    }

    /**
     * Returns issues found by a specific audit task.
     *
     * @param taskId The audit task identifier.
     * @return JSON array of issue objects.
     */
    fun getTaskIssues(taskId: String): JsonObject {
        val scanTask = stateManager.scanTasks[taskId]
            ?: return buildJsonObject { put("error", "Task not found: $taskId") }

        val task = scanTask.taskObject
        if (task !is Audit) {
            return buildJsonObject { put("error", "Task $taskId is not an audit task") }
        }

        // task.issues() may throw "Currently unsupported" on some Burp versions.
        // Fall back to fetching issues from the sitemap for the task's target URLs.
        val issues = try {
            task.issues()
        } catch (_: Exception) {
            // Fallback: get all issues from sitemap instead
            try {
                api.siteMap().issues()
            } catch (_: Exception) {
                return buildJsonObject {
                    put("task_id", taskId)
                    put("issue_count", 0)
                    put("issues", buildJsonArray {})
                    put("note", "task.issues() not supported in this Burp version; use scanner_get_all_issues for sitemap issues")
                }
            }
        }

        return buildJsonObject {
            put("task_id", taskId)
            put("issue_count", issues.size)
            put("issues", serializeIssues(issues))
        }
    }

    /**
     * Returns all issues from the site map, with optional filtering.
     *
     * @param urlPrefix Optional URL prefix filter.
     * @param severity Optional severity filter (HIGH, MEDIUM, LOW, INFORMATION).
     * @param confidence Optional confidence filter (CERTAIN, FIRM, TENTATIVE).
     * @param maxResults Maximum number of results to return.
     * @return JSON object with issues array.
     */
    fun getAllIssues(
        urlPrefix: String?,
        severity: String?,
        confidence: String?,
        maxResults: Int?
    ): JsonObject {
        return try {
            val allIssues = if (urlPrefix != null) {
                api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
            } else {
                api.siteMap().issues()
            }

            val filteredIssues = allIssues.filter { issue ->
                val severityMatch = severity == null ||
                    issue.severity().name.equals(severity, ignoreCase = true)
                val confidenceMatch = confidence == null ||
                    issue.confidence().name.equals(confidence, ignoreCase = true)
                severityMatch && confidenceMatch
            }

            val limited = if (maxResults != null && maxResults > 0) {
                filteredIssues.take(maxResults)
            } else {
                filteredIssues
            }

            buildJsonObject {
                put("total_unfiltered", allIssues.size)
                put("total_filtered", filteredIssues.size)
                put("returned", limited.size)
                put("issues", serializeIssues(limited))
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to get issues: ${e.message}")
            }
        }
    }

    /**
     * Generates a scan report in HTML or XML format.
     *
     * @param format Report format: "HTML" or "XML".
     * @param urlPrefix Optional URL prefix to filter issues.
     * @param severityFilter Optional list of severities to include.
     * @param outputPath File system path to write the report.
     * @return JSON object confirming report generation.
     */
    fun generateReport(
        format: String,
        urlPrefix: String?,
        severityFilter: List<String>?,
        outputPath: String
    ): JsonObject {
        return try {
            val allIssues = if (urlPrefix != null) {
                api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
            } else {
                api.siteMap().issues()
            }

            val filteredIssues = if (!severityFilter.isNullOrEmpty()) {
                allIssues.filter { issue ->
                    severityFilter.any { it.equals(issue.severity().name, ignoreCase = true) }
                }
            } else {
                allIssues
            }

            val reportFormat = when (format.uppercase()) {
                "XML" -> burp.api.montoya.scanner.ReportFormat.XML
                else -> burp.api.montoya.scanner.ReportFormat.HTML
            }

            // Confine writes to a reports directory. Without this, an attacker-
            // controlled (or prompt-injected) outputPath is an arbitrary file-write
            // primitive (e.g. ~/.bashrc, autostart entries). Absolute paths outside
            // the base and ".." traversal are rejected; everything else resolves
            // under <user.home>/.burpmcp-ultra/reports/.
            val baseDir = java.io.File(System.getProperty("user.home"), ".burpmcp-ultra/reports").canonicalFile
            baseDir.mkdirs()
            val requested = java.io.File(outputPath)
            val target = (if (requested.isAbsolute) requested else java.io.File(baseDir, outputPath)).canonicalFile
            if (target.path != baseDir.path && !target.path.startsWith(baseDir.path + java.io.File.separator)) {
                return buildJsonObject {
                    put("error", "output_path escapes the allowed reports directory ($baseDir): $outputPath")
                }
            }
            target.parentFile?.mkdirs()

            api.scanner().generateReport(filteredIssues, reportFormat, target.toPath())

            buildJsonObject {
                put("report_generated", true)
                put("format", format.uppercase())
                put("output_path", target.path)
                put("issue_count", filteredIssues.size)
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to generate report: ${e.message}")
            }
        }
    }

    /**
     * Creates a custom audit issue and adds it to the site map.
     *
     * @return JSON object confirming issue creation.
     */
    fun createCustomIssue(
        name: String,
        detail: String?,
        remediation: String?,
        severity: String,
        confidence: String,
        url: String,
        request: String?,
        response: String?
    ): JsonObject {
        return try {
            val issueSeverity = when (severity.uppercase()) {
                "HIGH" -> AuditIssueSeverity.HIGH
                "MEDIUM" -> AuditIssueSeverity.MEDIUM
                "LOW" -> AuditIssueSeverity.LOW
                else -> AuditIssueSeverity.INFORMATION
            }

            val issueConfidence = when (confidence.uppercase()) {
                "CERTAIN" -> AuditIssueConfidence.CERTAIN
                "FIRM" -> AuditIssueConfidence.FIRM
                else -> AuditIssueConfidence.TENTATIVE
            }

            var requestResponse: HttpRequestResponse? = null
            if (request != null && response != null) {
                val reqBytes = Base64.getDecoder().decode(request)
                val httpRequest = HttpRequest.httpRequest(BurpByteArray.byteArray(*reqBytes))
                val respBytes = Base64.getDecoder().decode(response)
                val httpResponse = HttpResponse.httpResponse(BurpByteArray.byteArray(*respBytes))
                requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
            }

            val issue = AuditIssue.auditIssue(
                name,
                detail ?: "",
                remediation ?: "",
                url,
                issueSeverity,
                issueConfidence,
                null, // background
                null, // remediation background
                issueSeverity, // typicalSeverity
                if (requestResponse != null) listOf(requestResponse) else emptyList()
            )

            api.siteMap().add(issue)

            buildJsonObject {
                put("created", true)
                put("name", name)
                put("url", url)
                put("severity", severity.uppercase())
                put("confidence", confidence.uppercase())
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to create issue: ${e.message}")
            }
        }
    }

    /**
     * Imports a BCheck script into the scanner.
     *
     * @param script The BCheck script content.
     * @return JSON object confirming import.
     */
    fun importBCheck(script: String): JsonObject {
        return try {
            val result = api.scanner().bChecks().importBCheck(script)
            when (result.status()) {
                burp.api.montoya.scanner.bchecks.BCheckImportResult.Status.LOADED_WITHOUT_ERRORS ->
                    buildJsonObject {
                        put("imported", true)
                        put("script_length", script.length)
                    }
                else ->
                    // LOADED_WITH_ERRORS: Burp parsed the script but rejected it.
                    // Report the import errors instead of a fake success.
                    buildJsonObject {
                        put("imported", false)
                        put("status", "error")
                        put("errors", buildJsonArray { result.importErrors().forEach { add(it) } })
                        put("hint", "Fix the reported BCheck errors and re-import.")
                    }
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "BCheck import is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to import BCheck: ${e.message}")
            }
        }
    }

    /**
     * Registers a dynamic scan check (passive or active) that pattern-matches
     * responses and optionally sends active probes.
     *
     * @param checkName Unique name for the scan check registration.
     * @param checkType "passive" or "active".
     * @param issueName Name of the issue to report when a match is found.
     * @param severity Issue severity: HIGH, MEDIUM, LOW, INFORMATION.
     * @param confidence Issue confidence: CERTAIN, FIRM, TENTATIVE.
     * @param detail Issue detail text.
     * @param remediation Issue remediation text.
     * @param passiveResponseMatch Regex to match against response body (passive checks).
     * @param passiveHeaderMatch Regex to match against response headers (passive checks).
     * @param activePayloads List of payload strings to inject (active checks).
     * @param activeResponseMatch Regex to match in the response after payload injection (active checks).
     * @return JSON object confirming registration.
     */
    fun registerScanCheck(
        checkName: String,
        checkType: String,
        issueName: String,
        severity: String,
        confidence: String,
        detail: String,
        remediation: String,
        passiveResponseMatch: String?,
        passiveHeaderMatch: String?,
        activePayloads: List<String>?,
        activeResponseMatch: String?
    ): JsonObject {
        return try {
            val issueSeverity = when (severity.uppercase()) {
                "HIGH" -> AuditIssueSeverity.HIGH
                "MEDIUM" -> AuditIssueSeverity.MEDIUM
                "LOW" -> AuditIssueSeverity.LOW
                else -> AuditIssueSeverity.INFORMATION
            }

            val issueConfidence = when (confidence.uppercase()) {
                "CERTAIN" -> AuditIssueConfidence.CERTAIN
                "FIRM" -> AuditIssueConfidence.FIRM
                else -> AuditIssueConfidence.TENTATIVE
            }

            val scanCheck = object : ScanCheck {
                override fun passiveAudit(baseRequestResponse: HttpRequestResponse): AuditResult {
                    if (checkType.equals("active", ignoreCase = true)) {
                        return AuditResult.auditResult(emptyList())
                    }

                    val issues = mutableListOf<AuditIssue>()
                    val responseBody = baseRequestResponse.response()?.bodyToString() ?: ""
                    val responseHeaders = baseRequestResponse.response()?.headers()
                        ?.joinToString("\r\n") { "${it.name()}: ${it.value()}" } ?: ""

                    var matched = false

                    if (passiveResponseMatch != null) {
                        val regex = Regex(passiveResponseMatch, RegexOption.IGNORE_CASE)
                        if (regex.containsMatchIn(responseBody)) {
                            matched = true
                        }
                    }

                    if (!matched && passiveHeaderMatch != null) {
                        val regex = Regex(passiveHeaderMatch, RegexOption.IGNORE_CASE)
                        if (regex.containsMatchIn(responseHeaders)) {
                            matched = true
                        }
                    }

                    if (matched) {
                        val url = baseRequestResponse.request()?.url() ?: ""
                        val issue = AuditIssue.auditIssue(
                            issueName,
                            detail,
                            remediation,
                            url,
                            issueSeverity,
                            issueConfidence,
                            null,
                            null,
                            issueSeverity,
                            baseRequestResponse
                        )
                        issues.add(issue)
                    }

                    return AuditResult.auditResult(issues)
                }

                override fun activeAudit(
                    baseRequestResponse: HttpRequestResponse,
                    insertionPoint: AuditInsertionPoint
                ): AuditResult {
                    if (checkType.equals("passive", ignoreCase = true)) {
                        return AuditResult.auditResult(emptyList())
                    }

                    val issues = mutableListOf<AuditIssue>()
                    val payloads = activePayloads ?: return AuditResult.auditResult(emptyList())
                    val matchRegex = activeResponseMatch?.let {
                        Regex(it, RegexOption.IGNORE_CASE)
                    } ?: return AuditResult.auditResult(emptyList())

                    for (payload in payloads) {
                        try {
                            val modifiedRequest = insertionPoint.buildHttpRequestWithPayload(
                                BurpByteArray.byteArray(payload)
                            )

                            val httpService = baseRequestResponse.httpService()
                                ?: continue

                            val checkRequestResponse = api.http().sendRequest(
                                modifiedRequest.withService(httpService)
                            )

                            val respBody = checkRequestResponse.response()?.bodyToString() ?: ""

                            if (matchRegex.containsMatchIn(respBody)) {
                                val url = baseRequestResponse.request()?.url() ?: ""
                                val matchDetail = "$detail\n\nPayload: $payload\nMatch found in response body."
                                val issue = AuditIssue.auditIssue(
                                    issueName,
                                    matchDetail,
                                    remediation,
                                    url,
                                    issueSeverity,
                                    issueConfidence,
                                    null,
                                    null,
                                    issueSeverity,
                                    baseRequestResponse, checkRequestResponse
                                )
                                issues.add(issue)
                            }
                        } catch (_: Exception) {
                            // Skip payloads that fail to send
                        }
                    }

                    return AuditResult.auditResult(issues)
                }

                override fun consolidateIssues(existingIssue: AuditIssue, newIssue: AuditIssue): ConsolidationAction {
                    return if (existingIssue.name() == newIssue.name() &&
                        existingIssue.baseUrl() == newIssue.baseUrl()) {
                        ConsolidationAction.KEEP_EXISTING
                    } else {
                        ConsolidationAction.KEEP_BOTH
                    }
                }
            }

            val registration: Registration = api.scanner().registerScanCheck(scanCheck)
            stateManager.registeredScanChecks.add(checkName)
            // Retain the Registration so the check can be deregistered later
            // (via unregisterScanCheck or on extension unload). Previously this
            // handle was discarded, leaking the check with no way to remove it.
            stateManager.scanCheckRegistrations.put(checkName, registration)
                ?.let { previous -> try { previous.deregister() } catch (_: Exception) {} }

            buildJsonObject {
                put("registered", true)
                put("check_name", checkName)
                put("check_type", checkType)
                put("issue_name", issueName)
            }
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Scanner API is not available in Burp Suite Community Edition")
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to register scan check: ${e.message}")
            }
        }
    }

    /**
     * Deregisters a scan check previously registered via [registerScanCheck].
     *
     * Uses the retained Montoya [Registration] handle to remove the check
     * from Burp's scanner, then drops it from internal tracking.
     *
     * @param checkName The name used when the check was registered.
     * @return JSON object confirming removal or reporting an error.
     */
    fun unregisterScanCheck(checkName: String): JsonObject {
        val registration = stateManager.scanCheckRegistrations[checkName]
            ?: return buildJsonObject { put("error", "Scan check not found: $checkName") }

        return try {
            registration.deregister()
            stateManager.scanCheckRegistrations.remove(checkName)
            stateManager.registeredScanChecks.remove(checkName)
            buildJsonObject {
                put("check_name", checkName)
                put("unregistered", true)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("check_name", checkName)
                put("error", "Failed to unregister scan check: ${e.message}")
            }
        }
    }

    /**
     * Creates an [AuditIssueHandler] that emits "scanner.issue" events on
     * the [EventBus] whenever Burp reports a new audit issue.
     *
     * Registered once during extension initialization in
     * [BurpMcpUltraExtension.registerBurpHandlers].
     */
    fun createIssueHandler(): AuditIssueHandler {
        return AuditIssueHandler { issue ->
            val data = serializeIssue(issue)
            eventBus.emit("scanner.issue", data)
        }
    }

    // ---------------------------------------------------------------
    // Serialization helpers
    // ---------------------------------------------------------------

    /**
     * Serializes a list of [AuditIssue] objects to a [JsonArray].
     */
    private fun serializeIssues(issues: List<AuditIssue>): JsonArray {
        return buildJsonArray {
            issues.forEach { issue ->
                add(serializeIssue(issue))
            }
        }
    }

    /**
     * Serializes a single [AuditIssue] to a [JsonObject].
     */
    private fun serializeIssue(issue: AuditIssue): JsonObject {
        return buildJsonObject {
            put("name", issue.name())
            put("url", issue.baseUrl())
            put("severity", issue.severity().name)
            put("confidence", issue.confidence().name)
            put("detail", issue.detail() ?: "")
            put("remediation", issue.remediation() ?: "")
            put("type_index", issue.definition()?.typeIndex()?.toLong() ?: 0L)

            // Serialize request/response pairs
            val reqRespPairs = try {
                issue.requestResponses() ?: emptyList()
            } catch (_: Exception) {
                emptyList()
            }

            put("request_responses", buildJsonArray {
                reqRespPairs.forEach { rr ->
                    add(buildJsonObject {
                        try {
                            val req = rr.request()
                            put("request", req?.toString() ?: "")
                            put("request_url", req?.url() ?: "")
                            put("request_method", req?.method() ?: "")
                        } catch (_: Exception) {
                            put("request", "")
                        }
                        try {
                            val resp = rr.response()
                            put("response_status", resp?.statusCode()?.toLong() ?: 0L)
                            put("response_length", resp?.body()?.length()?.toLong() ?: 0L)
                        } catch (_: Exception) {
                            put("response_status", 0L)
                        }
                    })
                }
            })
        }
    }
}
