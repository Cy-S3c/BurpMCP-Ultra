package com.burpmcp.ultra.tools.intruder

import com.burpmcp.ultra.bridge.IntruderBridge
import com.burpmcp.ultra.state.StateManager
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object IntruderTools {

    fun register(server: Server, bridge: IntruderBridge, stateManager: StateManager) {

        server.addTool(
            name = "intruder_send",
            description = "Send an HTTP request to Burp Suite's Intruder tool for automated attack " +
                "configuration. Creates a new Intruder tab with the specified request. " +
                "Parameters: request (raw HTTP request string), host (target hostname), " +
                "port (target port), use_tls (boolean), tab_name (optional tab name).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use TLS, default false") }
                    putJsonObject("tab_name") { put("type", "string"); put("description", "Optional Intruder tab name") }
                },
                required = listOf("request", "host", "port")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: request"}""")),
                        isError = true
                    )
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: host"}""")),
                        isError = true
                    )
                val port = args["port"]?.jsonPrimitive?.intOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: port"}""")),
                        isError = true
                    )
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull ?: false
                val tabName = args["tab_name"]?.jsonPrimitive?.contentOrNull

                val result = bridge.sendToIntruder(rawRequest, host, port, useTls, tabName)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "intruder_send_with_positions",
            description = "Send an HTTP request to Intruder with pre-defined payload insertion " +
                "point positions. Each position is a [start, end] byte offset pair marking " +
                "where payloads should be inserted. Parameters: request (raw HTTP request), " +
                "host (target hostname), port (target port), use_tls (boolean), " +
                "positions (array of [start, end] pairs), tab_name (optional tab name).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") { put("type", "integer"); put("description", "Target port") }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use TLS, default false") }
                    putJsonObject("positions") {
                        put("type", "array")
                        put("description", "Array of [start, end] byte offset pairs marking payload insertion points")
                        putJsonObject("items") { put("type", "array") }
                    }
                    putJsonObject("tab_name") { put("type", "string"); put("description", "Optional Intruder tab name") }
                },
                required = listOf("request", "host", "port", "positions")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val rawRequest = args["request"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: request"}""")),
                        isError = true
                    )
                val host = args["host"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: host"}""")),
                        isError = true
                    )
                val port = args["port"]?.jsonPrimitive?.intOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: port"}""")),
                        isError = true
                    )
                val useTls = args["use_tls"]?.jsonPrimitive?.booleanOrNull ?: false
                val tabName = args["tab_name"]?.jsonPrimitive?.contentOrNull

                val rawPositions = args["positions"]?.jsonArray
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: positions"}""")),
                        isError = true
                    )

                val positions = rawPositions.map { pos ->
                    when {
                        pos is JsonArray -> {
                            val start = pos[0].jsonPrimitive.int
                            val end = pos[1].jsonPrimitive.int
                            Pair(start, end)
                        }
                        pos is JsonObject -> {
                            val start = (pos["start"]?.jsonPrimitive?.intOrNull
                                ?: pos["0"]?.jsonPrimitive?.intOrNull)
                                ?: throw IllegalArgumentException("Position missing 'start' field")
                            val end = (pos["end"]?.jsonPrimitive?.intOrNull
                                ?: pos["1"]?.jsonPrimitive?.intOrNull)
                                ?: throw IllegalArgumentException("Position missing 'end' field")
                            Pair(start, end)
                        }
                        else -> throw IllegalArgumentException("Invalid position format: $pos")
                    }
                }

                val result = bridge.sendWithPositions(rawRequest, host, port, useTls, positions, tabName)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "intruder_register_payload_processor",
            description = "Register a custom payload processor with Intruder that transforms " +
                "payloads during attacks. Supported transform types: encode_base64, encode_url, " +
                "hash_md5, hash_sha1, hash_sha256, prefix (prepend string), suffix (append " +
                "string), regex_replace (apply regex replacement). Parameters: name (processor " +
                "name), transform_type (one of the supported types), prefix_value (string to " +
                "prepend, for prefix type), suffix_value (string to append, for suffix type), " +
                "regex_pattern (regex pattern, for regex_replace type), regex_replacement " +
                "(replacement string, for regex_replace type).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") { put("type", "string"); put("description", "Processor name") }
                    putJsonObject("transform_type") { put("type", "string"); put("description", "One of: encode_base64, encode_url, hash_md5, hash_sha1, hash_sha256, prefix, suffix, regex_replace") }
                    putJsonObject("prefix_value") { put("type", "string"); put("description", "String to prepend, for prefix type") }
                    putJsonObject("suffix_value") { put("type", "string"); put("description", "String to append, for suffix type") }
                    putJsonObject("regex_pattern") { put("type", "string"); put("description", "Regex pattern, for regex_replace type") }
                    putJsonObject("regex_replacement") { put("type", "string"); put("description", "Replacement string, for regex_replace type") }
                },
                required = listOf("name", "transform_type")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val name = args["name"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: name"}""")),
                        isError = true
                    )
                val transformType = args["transform_type"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: transform_type"}""")),
                        isError = true
                    )

                val validTypes = listOf(
                    "encode_base64", "encode_url",
                    "hash_md5", "hash_sha1", "hash_sha256",
                    "prefix", "suffix", "regex_replace"
                )
                if (transformType !in validTypes) {
                    return@addTool CallToolResult(
                        content = listOf(TextContent(
                            """{"error":"Invalid transform_type: $transformType. Valid types: ${validTypes.joinToString(", ")}"}"""
                        )),
                        isError = true
                    )
                }

                val params = mutableMapOf<String, String>()
                (args["prefix_value"]?.jsonPrimitive?.contentOrNull)?.let { params["prefix_value"] = it }
                (args["suffix_value"]?.jsonPrimitive?.contentOrNull)?.let { params["suffix_value"] = it }
                (args["regex_pattern"]?.jsonPrimitive?.contentOrNull)?.let { params["regex_pattern"] = it }
                (args["regex_replacement"]?.jsonPrimitive?.contentOrNull)?.let { params["regex_replacement"] = it }

                val result = bridge.registerPayloadProcessor(name, transformType, params)
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }
    }
}
