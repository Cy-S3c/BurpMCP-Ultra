package com.burpmcp.ultra.tools.events

import com.burpmcp.ultra.events.BurpEvent
import com.burpmcp.ultra.events.EventBus
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object EventsTools {

    fun register(server: Server, eventBus: EventBus) {

        // 1. events_get
        server.addTool(
            name = "events_get",
            description = "Retrieve events from the event bus using cursor-based polling. Returns events " +
                "whose ID is strictly greater than since_id. Use the last event's ID as the cursor " +
                "for subsequent polls. Parameters: since_id (number, return events after this ID; " +
                "defaults to 0 for all events), max_events (number, maximum events to return; " +
                "defaults to 200).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("since_id") { put("type", "integer"); put("description", "Return events after this ID (default 0)") }
                    putJsonObject("max_events") { put("type", "integer"); put("description", "Maximum events to return (default 200)") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val sinceId = args["since_id"]?.jsonPrimitive?.longOrNull ?: 0L
                val maxEvents = args["max_events"]?.jsonPrimitive?.intOrNull ?: 200

                val events = eventBus.getEvents(sinceId, maxEvents)
                val result = buildJsonObject {
                    put("since_id", sinceId)
                    put("returned", events.size)
                    put("last_id", eventBus.lastId())
                    put("buffer_size", eventBus.size())
                    put("events", serializeEvents(events))
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 2. events_get_by_type
        server.addTool(
            name = "events_get_by_type",
            description = "Retrieve events from the event bus filtered by event type(s). Supports " +
                "cursor-based polling. Parameters: types (array of strings, event types to filter " +
                "e.g. ['proxy.request', 'scanner.issue']), since_id (number, return events after " +
                "this ID; defaults to 0), max_events (number, maximum events to return; defaults to 200).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("types") {
                        put("type", "array")
                        put("description", "Event types to filter e.g. ['proxy.request', 'scanner.issue']")
                        putJsonObject("items") { put("type", "string") }
                    }
                    putJsonObject("since_id") { put("type", "integer"); put("description", "Return events after this ID (default 0)") }
                    putJsonObject("max_events") { put("type", "integer"); put("description", "Maximum events to return (default 200)") }
                },
                required = listOf("types")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val types = args["types"]?.jsonArray?.map { it.jsonPrimitive.content }
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: types (array of strings)"}""")),
                        isError = true
                    )

                val sinceId = args["since_id"]?.jsonPrimitive?.longOrNull ?: 0L
                val maxEvents = args["max_events"]?.jsonPrimitive?.intOrNull ?: 200

                val events = eventBus.getEventsByType(types, sinceId, maxEvents)
                val result = buildJsonObject {
                    put("since_id", sinceId)
                    putJsonArray("types") { types.forEach { add(it) } }
                    put("returned", events.size)
                    put("last_id", eventBus.lastId())
                    put("events", serializeEvents(events))
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 3. events_subscribe
        server.addTool(
            name = "events_subscribe",
            description = "Subscribe to real-time event notifications from the event bus. When " +
                "subscribed, matching events are buffered for retrieval. Returns a subscription " +
                "ID for later unsubscription. Parameters: types (array of strings, event types " +
                "to subscribe to; empty array subscribes to all events).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("types") {
                        put("type", "array")
                        put("description", "Event types to subscribe to; empty array subscribes to all events")
                        putJsonObject("items") { put("type", "string") }
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val types = args["types"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList()

                // Create a buffer for the subscription
                val subscriptionBuffer = java.util.concurrent.ConcurrentLinkedDeque<BurpEvent>()
                val subscriptionId = eventBus.subscribe(types) { event ->
                    subscriptionBuffer.addLast(event)
                    // Cap the subscription buffer at 1000 events
                    while (subscriptionBuffer.size > 1000) {
                        subscriptionBuffer.pollFirst()
                    }
                }

                val result = buildJsonObject {
                    put("subscription_id", subscriptionId)
                    put("status", "subscribed")
                    putJsonArray("types") { types.forEach { add(it) } }
                    put("note", if (types.isEmpty()) "Subscribed to all event types" else "Subscribed to ${types.size} event type(s)")
                    putJsonArray("resource_uris") {
                        add("burp://events")
                        types.forEach { type ->
                            add("burp://events/$type")
                        }
                    }
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 4. events_unsubscribe
        server.addTool(
            name = "events_unsubscribe",
            description = "Unsubscribe from event bus notifications. Removes a previously created " +
                "subscription by its ID. Parameters: subscription_id (string, the subscription " +
                "ID returned by events_subscribe).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("subscription_id") { put("type", "string"); put("description", "Subscription ID returned by events_subscribe") }
                },
                required = listOf("subscription_id")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val subscriptionId = args["subscription_id"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Missing required parameter: subscription_id"}""")),
                        isError = true
                    )

                eventBus.unsubscribe(subscriptionId)

                val result = buildJsonObject {
                    put("subscription_id", subscriptionId)
                    put("status", "unsubscribed")
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }

        // 5. events_clear
        server.addTool(
            name = "events_clear",
            description = "Clear all events from the event bus buffer and remove all subscriptions. " +
                "Use with caution as this is irreversible. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) { _ ->
            try {
                val sizeBefore = eventBus.size()
                eventBus.clear()

                val result = buildJsonObject {
                    put("status", "cleared")
                    put("events_removed", sizeBefore)
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent("""{"error":"${e.message}"}""")),
                    isError = true
                )
            }
        }
    }

    /**
     * Serializes a list of BurpEvent objects to a JsonArray.
     */
    private fun serializeEvents(events: List<BurpEvent>): JsonArray {
        return buildJsonArray {
            for (event in events) {
                addJsonObject {
                    put("id", event.id)
                    put("type", event.type)
                    put("timestamp", event.timestamp)
                    put("data", event.data)
                }
            }
        }
    }
}
