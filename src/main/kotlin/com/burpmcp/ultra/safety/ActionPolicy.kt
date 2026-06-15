package com.burpmcp.ultra.safety

/**
 * Operator-controlled gate for destructive / irreversible MCP tools.
 *
 * The previous design let the agent self-authorize (e.g. `burp_shutdown`'s
 * `prompt_user` defaulted to false and was agent-set). Governance must live
 * server-side and be unsettable by the agent: these tools are blocked unless
 * the operator has set the Burp preference `mcp_allow_destructive=true`.
 */
object ActionPolicy {

    /** Tools that shut down Burp or overwrite its configuration. */
    val DESTRUCTIVE_TOOLS = setOf(
        "burp_shutdown",
        "burp_import_project_config",
        "burp_import_user_config"
    )

    fun isDestructive(toolName: String): Boolean = toolName in DESTRUCTIVE_TOOLS

    /**
     * @param allowDestructive the operator preference (`mcp_allow_destructive`); the agent cannot set it.
     * @return true if [toolName] may run.
     */
    fun isAllowed(toolName: String, allowDestructive: Boolean): Boolean =
        !isDestructive(toolName) || allowDestructive
}
