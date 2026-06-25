package com.burpmcp.ultra.core

/**
 * Pure decision logic for `proxy_history_search`: maps a `search_in` value to which
 * parts of a history item should be scanned. Extracted from [ProxyBridge.searchHistory]
 * so it is unit-testable without Montoya.
 *
 * The original code only recognised "request"/"response"/"both"; any other value
 * (notably `search_in="url"`) set both flags false, scanned nothing, and silently
 * returned 0 matches. This adds first-class **url** scanning and makes unknown/blank
 * values fall back to scanning everything rather than nothing.
 */
object ProxyHistorySearch {

    /** Which parts of a history item to scan for the pattern. */
    data class Targets(val url: Boolean, val request: Boolean, val response: Boolean)

    fun targets(searchIn: String?): Targets = when (searchIn?.trim()?.lowercase()) {
        "url" -> Targets(url = true, request = false, response = false)
        "request" -> Targets(url = false, request = true, response = false)
        "response" -> Targets(url = false, request = false, response = true)
        // "both" / "all" / null / blank / anything unrecognised -> scan everything,
        // never silently match nothing.
        else -> Targets(url = true, request = true, response = true)
    }
}
