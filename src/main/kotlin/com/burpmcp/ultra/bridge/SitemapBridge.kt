package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.HttpService
import burp.api.montoya.sitemap.SiteMapFilter
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.http.message.HttpRequestResponse
import kotlinx.serialization.json.*

class SitemapBridge(private val api: MontoyaApi) {

    fun query(
        urlPrefix: String?,
        searchPattern: String?,
        maxResults: Int,
        includeRequest: Boolean,
        includeResponse: Boolean
    ): JsonArray {
        val filter = if (urlPrefix != null) {
            SiteMapFilter.prefixFilter(urlPrefix)
        } else {
            null
        }

        var entries = if (filter != null) {
            api.siteMap().requestResponses(filter)
        } else {
            api.siteMap().requestResponses()
        }

        if (searchPattern != null) {
            val regex = Regex(searchPattern, RegexOption.IGNORE_CASE)
            entries = entries.filter { entry ->
                val url = entry.request()?.url() ?: ""
                regex.containsMatchIn(url)
            }
        }

        val limited = entries.take(maxResults)

        return buildJsonArray {
            for (entry in limited) {
                addJsonObject {
                    val req = entry.request()
                    val resp = entry.response()

                    put("url", req?.url() ?: "unknown")
                    put("method", req?.method() ?: "unknown")
                    put("status_code", resp?.statusCode() ?: 0)
                    put("content_length", resp?.body()?.length() ?: 0)
                    put("mime_type", resp?.statedMimeType()?.toString() ?: "unknown")

                    if (includeRequest && req != null) {
                        put("request", req.toString())
                    }

                    if (includeResponse && resp != null) {
                        val responseStr = resp.toString()
                        if (responseStr.length > 100_000) {
                            put("response", responseStr.substring(0, 100_000) + "... [truncated]")
                            put("response_truncated", true)
                        } else {
                            put("response", responseStr)
                        }
                    }
                }
            }
        }
    }

    fun getIssues(urlPrefix: String?, severity: String?): JsonArray {
        var issues = if (urlPrefix != null) {
            api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix))
        } else {
            api.siteMap().issues()
        }

        if (severity != null) {
            val targetSeverity = try {
                AuditIssueSeverity.valueOf(severity.uppercase())
            } catch (_: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid severity '$severity'. Allowed: high, medium, low, information")
            }
            issues = issues.filter { it.severity() == targetSeverity }
        }

        return buildJsonArray {
            for (issue in issues) {
                addJsonObject {
                    put("name", issue.name())
                    put("detail", issue.detail() ?: "")
                    put("remediation", issue.remediation() ?: "")
                    put("severity", issue.severity().toString())
                    put("confidence", issue.confidence().toString())
                    put("base_url", issue.baseUrl())

                    val requestResponses = issue.requestResponses()
                    if (requestResponses != null && requestResponses.isNotEmpty()) {
                        putJsonArray("affected_urls") {
                            for (rr in requestResponses) {
                                val url = rr.request()?.url()
                                if (url != null) add(url)
                            }
                        }
                        put("request_response_count", requestResponses.size)
                    }
                }
            }
        }
    }

    fun addRequest(
        request: String,
        response: String?,
        host: String,
        port: Int,
        useTls: Boolean
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        val httpRequest = HttpRequest.httpRequest(httpService, request)

        val httpResponse = if (response != null) {
            HttpResponse.httpResponse(response)
        } else {
            HttpResponse.httpResponse()
        }

        val requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)

        api.siteMap().add(requestResponse)

        return buildJsonObject {
            put("status", "added")
            put("url", httpRequest.url())
            put("method", httpRequest.method())
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("has_response", response != null)
        }
    }

    fun addIssue(
        name: String,
        detail: String,
        remediation: String?,
        severity: String,
        confidence: String,
        url: String,
        request: String?,
        response: String?
    ): JsonObject {
        val issueSeverity = try {
            AuditIssueSeverity.valueOf(severity.uppercase())
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid severity '$severity'. Allowed: high, medium, low, information")
        }

        val issueConfidence = try {
            AuditIssueConfidence.valueOf(confidence.uppercase())
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid confidence '$confidence'. Allowed: certain, firm, tentative")
        }

        val requestResponses = mutableListOf<HttpRequestResponse>()
        if (request != null) {
            val httpRequest = HttpRequest.httpRequest(request)
            val httpResponse = if (response != null) {
                HttpResponse.httpResponse(response)
            } else {
                HttpResponse.httpResponse()
            }
            val rr = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
            requestResponses.add(rr)
        }

        val auditIssue = AuditIssue.auditIssue(
            name,
            detail,
            remediation ?: "",
            url,
            issueSeverity,
            issueConfidence,
            null, // background
            null, // remediation background
            issueSeverity, // typicalSeverity
            requestResponses
        )

        api.siteMap().add(auditIssue)

        return buildJsonObject {
            put("status", "added")
            put("name", name)
            put("severity", issueSeverity.toString())
            put("confidence", issueConfidence.toString())
            put("url", url)
            put("has_request_response", request != null)
        }
    }
}
