package com.burpmcp.ultra.bridge

import com.burpmcp.ultra.safety.SafeRegex
import com.burpmcp.ultra.state.SessionRule

/**
 * Pure logic for [SessionRule] evaluation: scope matching, value extraction
 * from a response, and template rendering for injection. Kept free of the
 * Montoya API so it is unit-testable; the bridge supplies resolved header
 * values, bodies, and the suite-scope flag.
 */
object SessionRuleEngine {

    /**
     * Whether this rule applies to [url]. `all` always matches; `custom` matches
     * its [SessionRule.scopePattern] regex; `suite` defers to [suiteInScope]
     * (which the caller computes from `api.scope().isInScope`).
     */
    fun inScope(rule: SessionRule, url: String, suiteInScope: Boolean): Boolean = when (rule.scope.lowercase()) {
        "all" -> true
        "suite" -> suiteInScope
        "custom" -> rule.scopePattern != null && SafeRegex.containsMatchIn(rule.scopePattern, url)
        else -> false
    }

    /**
     * Extracts a value using [SessionRule.extractRegex] from either the supplied
     * [headerValue] (when `extractFrom == "header"`) or [body]. Returns the first
     * capture group, or the whole match if the pattern has no group, or null if
     * there is no match (or the named header was absent).
     */
    fun extract(rule: SessionRule, headerValue: String?, body: String): String? {
        val source = when (rule.extractFrom.lowercase()) {
            "header" -> headerValue ?: return null
            "body" -> body
            else -> return null
        }
        val m = SafeRegex.find(rule.extractRegex, source) ?: return null
        return if (m.groupValues.size > 1) m.groupValues[1] else m.value
    }

    /** Renders [template], replacing the `{value}` placeholder with [value]. */
    fun render(template: String, value: String): String = template.replace("{value}", value)
}
