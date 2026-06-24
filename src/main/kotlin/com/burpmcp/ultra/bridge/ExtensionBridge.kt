package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import com.burpmcp.ultra.state.StateManager
import kotlinx.serialization.json.*

/**
 * Bridge wrapping the Montoya Extension API and runtime state.
 *
 * Provides introspection into the BurpMCP-Ultra extension itself:
 * its name, version, filename, registered handlers, active rules,
 * and MCP server information.
 */
class ExtensionBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager
) {

    /**
     * Returns comprehensive information about the BurpMCP-Ultra extension
     * including runtime state, registered handlers, and MCP server details.
     */
    fun getInfo(): JsonObject {
        return try {
            val extension = api.extension()

            buildJsonObject {
                // Extension identity
                put("name", extension.filename() ?: "BurpMCP-Ultra")
                put("filename", extension.filename() ?: "unknown")
                put("is_bapp", extension.isBapp())

                // MCP server info. Both ports are plain MCP SSE transports; there is
                // no Streamable HTTP or stdio transport (those were never implemented).
                put("mcp", buildJsonObject {
                    put("version", "2.1.0")
                    put("sse_port_primary", 9876)
                    put("sse_port_secondary", 9877)
                    put("dashboard_port", 9878)
                    put("auth_required", true)
                    put("transports", buildJsonArray {
                        add("SSE (primary)")
                        add("SSE (secondary)")
                    })
                })

                // Burp Suite version
                val version = api.burpSuite().version()
                put("burp_version", buildJsonObject {
                    put("product", version.name())
                    put("major", version.major())
                    put("minor", version.minor())
                    put("build", version.build())
                    put("edition", version.edition().name)
                })

                // Runtime state summary
                put("state", buildJsonObject {
                    put("proxy_rules", stateManager.proxyRules.size)
                    put("traffic_rules", stateManager.trafficRules.size)
                    put("session_rules", stateManager.sessionRules.size)
                    put("websocket_connections", stateManager.websocketConnections.size)
                    put("active_scan_tasks", stateManager.scanTasks.size)
                    put("collaborator_clients", stateManager.collaboratorClients.size)
                    put("registered_scan_checks", stateManager.registeredScanChecks.size)
                    put("registered_payload_processors", stateManager.registeredPayloadProcessors.size)
                    put("websocket_intercept_rules", stateManager.websocketInterceptRules.size)
                })

                // Registered handler counts
                put("registered_handlers", buildJsonObject {
                    put("scan_checks", stateManager.registeredScanChecks.toList().let { checks ->
                        buildJsonArray { checks.forEach { add(it) } }
                    })
                    put("payload_processors", stateManager.registeredPayloadProcessors.toList().let { processors ->
                        buildJsonArray { processors.forEach { add(it) } }
                    })
                })
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to retrieve extension info: ${e.message}")
            }
        }
    }
}
