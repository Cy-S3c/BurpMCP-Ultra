package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.ShutdownOptions
import burp.api.montoya.burpsuite.TaskExecutionEngine
import kotlinx.serialization.json.*

class BurpSuiteBridge(private val api: MontoyaApi) {

    /**
     * Returns version information about the running Burp Suite instance.
     */
    fun getVersion(): JsonObject {
        val suite = api.burpSuite()
        val version = suite.version()
        return buildJsonObject {
            put("product_name", version.name())
            put("version", "${version.major()}.${version.minor()}")
            put("major", version.major())
            put("minor", version.minor())
            put("build", version.build())
            put("edition", version.edition().name)
        }
    }

    /**
     * Exports project-level configuration as JSON.
     *
     * @param paths Optional list of configuration paths to export. If empty,
     *              exports all project options.
     * @return The JSON configuration string.
     */
    fun exportProjectConfig(paths: List<String>): String {
        return if (paths.isEmpty()) {
            api.burpSuite().exportProjectOptionsAsJson()
        } else {
            api.burpSuite().exportProjectOptionsAsJson(*paths.toTypedArray())
        }
    }

    /**
     * Exports user-level configuration as JSON.
     *
     * @param paths Optional list of configuration paths to export. If empty,
     *              exports all user options.
     * @return The JSON configuration string.
     */
    fun exportUserConfig(paths: List<String>): String {
        return if (paths.isEmpty()) {
            api.burpSuite().exportUserOptionsAsJson()
        } else {
            api.burpSuite().exportUserOptionsAsJson(*paths.toTypedArray())
        }
    }

    /**
     * Imports project-level configuration from a JSON string.
     *
     * @param configJson The JSON configuration to import.
     * @return JSON object confirming the import.
     */
    fun importProjectConfig(configJson: String): JsonObject {
        api.burpSuite().importProjectOptionsFromJson(configJson)
        return buildJsonObject {
            put("status", "imported")
            put("type", "project")
        }
    }

    /**
     * Imports user-level configuration from a JSON string.
     *
     * @param configJson The JSON configuration to import.
     * @return JSON object confirming the import.
     */
    fun importUserConfig(configJson: String): JsonObject {
        api.burpSuite().importUserOptionsFromJson(configJson)
        return buildJsonObject {
            put("status", "imported")
            put("type", "user")
        }
    }

    /**
     * Returns the current state of the task execution engine
     * (RUNNING or PAUSED).
     */
    fun getTaskEngineState(): JsonObject {
        val state = api.burpSuite().taskExecutionEngine().getState()
        return buildJsonObject {
            put("state", state.name.lowercase())
        }
    }

    /**
     * Sets the task execution engine to the specified state.
     *
     * @param state Must be "running" or "paused".
     * @return JSON object confirming the state change.
     */
    fun setTaskEngineState(state: String): JsonObject {
        val engine = api.burpSuite().taskExecutionEngine()
        val targetState = when (state.lowercase()) {
            "running" -> TaskExecutionEngine.TaskExecutionEngineState.RUNNING
            "paused" -> TaskExecutionEngine.TaskExecutionEngineState.PAUSED
            else -> throw IllegalArgumentException(
                "Invalid state: '$state'. Must be 'running' or 'paused'."
            )
        }
        engine.setState(targetState)
        return buildJsonObject {
            put("status", "updated")
            put("state", state.lowercase())
        }
    }

    /**
     * Returns the command line arguments that were passed to Burp Suite.
     */
    fun getCommandLineArgs(): JsonObject {
        val args = api.burpSuite().commandLineArguments()
        return buildJsonObject {
            putJsonArray("arguments") {
                for (arg in args) {
                    add(arg)
                }
            }
            put("count", args.size)
        }
    }

    /**
     * Initiates a Burp Suite shutdown.
     *
     * @param promptUser If true, prompts the user before shutting down.
     * @return JSON object confirming the shutdown was initiated.
     */
    fun shutdown(promptUser: Boolean): JsonObject {
        if (promptUser) {
            api.burpSuite().shutdown(ShutdownOptions.PROMPT_USER)
        } else {
            api.burpSuite().shutdown()
        }
        return buildJsonObject {
            put("status", "shutdown_initiated")
            put("prompt_user", promptUser)
        }
    }

    /**
     * Operator preference (Burp pref `mcp_allow_destructive`) gating destructive
     * tools. The agent cannot set it. Defaults to false (destructive tools blocked).
     */
    fun destructiveAllowed(): Boolean =
        try { api.persistence().preferences().getBoolean("mcp_allow_destructive") ?: false } catch (_: Exception) { false }
}
