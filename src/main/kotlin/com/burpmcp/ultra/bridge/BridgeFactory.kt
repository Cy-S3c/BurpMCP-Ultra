package com.burpmcp.ultra.bridge

import burp.api.montoya.MontoyaApi
import com.burpmcp.ultra.events.EventBus
import com.burpmcp.ultra.state.StateManager

class BridgeFactory {

    /**
     * Container holding all bridge instances. Each bridge wraps a specific
     * area of the Montoya API and exposes MCP-friendly methods.
     */
    data class Bridges(
        val proxy: ProxyBridge,
        val http: HttpBridge,
        val scanner: ScannerBridge,
        val collaborator: CollaboratorBridge,
        val repeater: RepeaterBridge,
        val intruder: IntruderBridge,
        val sitemap: SitemapBridge,
        val scope: ScopeBridge,
        val comparer: ComparerBridge,
        val decoder: DecoderBridge,
        val organizer: OrganizerBridge,
        val websocket: WebSocketBridge,
        val burpSuite: BurpSuiteBridge,
        val utilities: UtilitiesBridge,
        val ai: AiBridge,
        val bambda: BambdaBridge,
        val persistence: PersistenceBridge,
        val project: ProjectBridge,
        val logging: LoggingBridge,
        val extension: ExtensionBridge,
        val bcheck: BCheckBridge,
        val scanCheck: ScanCheckBridge,
        val apiImport: ApiImportBridge,
        val passiveIntel: PassiveIntelBridge,
        val analysis: AnalysisBridge,
        val jwt: JwtBridge,
        val findings: FindingsBridge,
        val recon: ReconBridge,
        val graphql: GraphQlBridge,
        val webProbe: WebProbeBridge,
        val accessControl: AccessControlBridge
    )

    companion object {
        /**
         * Creates all bridge instances in one shot. Bridges that need event
         * emission or state tracking receive the shared [eventBus] and
         * [stateManager] references; bridges that are stateless only
         * receive the Montoya [api].
         */
        fun createAll(
            api: MontoyaApi,
            eventBus: EventBus,
            stateManager: StateManager
        ): Bridges {
            return Bridges(
                proxy = ProxyBridge(api, eventBus, stateManager),
                http = HttpBridge(api, eventBus, stateManager),
                scanner = ScannerBridge(api, eventBus, stateManager),
                collaborator = CollaboratorBridge(api, eventBus, stateManager),
                repeater = RepeaterBridge(api),
                intruder = IntruderBridge(api, stateManager),
                sitemap = SitemapBridge(api),
                scope = ScopeBridge(api, eventBus),
                comparer = ComparerBridge(api),
                decoder = DecoderBridge(api),
                organizer = OrganizerBridge(api),
                websocket = WebSocketBridge(api, eventBus, stateManager),
                burpSuite = BurpSuiteBridge(api),
                utilities = UtilitiesBridge(api),
                ai = AiBridge(api),
                bambda = BambdaBridge(api),
                persistence = PersistenceBridge(api),
                project = ProjectBridge(api),
                logging = LoggingBridge(api),
                extension = ExtensionBridge(api, stateManager),
                bcheck = BCheckBridge(api, stateManager),
                scanCheck = ScanCheckBridge(api, stateManager),
                apiImport = ApiImportBridge(api, stateManager),
                passiveIntel = PassiveIntelBridge(api),
                analysis = AnalysisBridge(api),
                jwt = JwtBridge(),
                findings = FindingsBridge(stateManager),
                recon = ReconBridge(api),
                graphql = GraphQlBridge(api),
                webProbe = WebProbeBridge(api),
                accessControl = AccessControlBridge(api)
            )
        }
    }
}
