/**
 * File: 06_threat_dashboard.ts
 * Topic: Defensive Security Operations - Metric Aggregator & Event Parser
 * Language: TypeScript (Node.js/ES2022)
 * Description: Stream parser, metric aggregator, and event dispatcher designed to parse,
 *              structure, and filter incoming telemetry events in real time.
 */

export namespace SecurityOperations {

    export enum AlertSeverity {
        LOW = "LOW",
        MEDIUM = "MEDIUM",
        HIGH = "HIGH",
        CRITICAL = "CRITICAL"
    }

    export interface SecurityEvent {
        id: string;
        timestamp: number;
        sourceIp: string;
        eventType: string;
        severity: AlertSeverity;
        payload: Record<string, unknown>;
        tags: string[];
    }

    export interface SystemMetrics {
        processedEvents: number;
        criticalAlertCount: number;
        activeSources: Set<string>;
        bytesAnalyzed: number;
    }

    export type SecurityEventListener = (event: SecurityEvent) => void;

    /**
     * Engine responsible for validating and categorizing raw JSON event strings.
     */
    export class EventParser {
        public static parseRawEvent(rawJson: string): SecurityEvent | null {
            try {
                const parsed = JSON.parse(rawJson);
                
                if (!parsed.id || !parsed.sourceIp || !parsed.eventType) {
                    throw new Error("Missing mandatory SecurityEvent fields");
                }

                return {
                    id: String(parsed.id),
                    timestamp: Number(parsed.timestamp) || Date.now(),
                    sourceIp: String(parsed.sourceIp),
                    eventType: String(parsed.eventType),
                    severity: EventParser.validateSeverity(parsed.severity),
                    payload: typeof parsed.payload === 'object' ? parsed.payload : {},
                    tags: Array.isArray(parsed.tags) ? parsed.tags.map(String) : []
                };
            } catch (error) {
                console.error(`[Parser Error] Failed to process incoming JSON payload: ${(error as Error).message}`);
                return null;
            }
        }

        private static validateSeverity(severityStr: unknown): AlertSeverity {
            const str = String(severityStr).toUpperCase();
            if (Object.values(AlertSeverity).includes(str as AlertSeverity)) {
                return str as AlertSeverity;
            }
            return AlertSeverity.LOW;
        }
    }

    /**
     * Core telemetry aggregator and event bus controller.
     */
    export class ThreatDashboardEngine {
        private metrics: SystemMetrics;
        private listeners: Map<string, SecurityEventListener[]>;
        private eventHistory: SecurityEvent[];
        private readonly maxHistorySize: number;

        constructor(maxHistorySize: number = 500) {
            this.maxHistorySize = maxHistorySize;
            this.eventHistory = [];
            this.listeners = new Map();
            this.metrics = {
                processedEvents: 0,
                criticalAlertCount: 0,
                activeSources: new Set<string>(),
                bytesAnalyzed: 0
            };
        }

        public subscribe(eventType: string, listener: SecurityEventListener): void {
            if (!this.listeners.has(eventType)) {
                this.listeners.set(eventType, []);
            }
            this.listeners.get(eventType)?.push(listener);
        }

        public ingestRawPayload(rawJson: string): boolean {
            this.metrics.bytesAnalyzed += rawJson.length;
            const event = EventParser.parseRawEvent(rawJson);

            if (!event) {
                return false;
            }

            this.processEvent(event);
            return true;
        }

        private processEvent(event: SecurityEvent): void {
            this.metrics.processedEvents++;
            this.metrics.activeSources.add(event.sourceIp);

            if (event.severity === AlertSeverity.CRITICAL) {
                this.metrics.criticalAlertCount++;
            }

            // Store in bounded history
            this.eventHistory.push(event);
            if (this.eventHistory.length > this.maxHistorySize) {
                this.eventHistory.shift();
            }

            // Dispatch to registered event listeners
            this.notifyListeners(event);
        }

        private notifyListeners(event: SecurityEvent): void {
            const handlers = this.listeners.get(event.eventType) || [];
            const wildcardHandlers = this.listeners.get("*") || [];

            [...handlers, ...wildcardHandlers].forEach((listener) => {
                try {
                    listener(event);
                } catch (err) {
                    console.error(`[Listener Error] Exception in handler for ${event.eventType}:`, err);
                }
            });
        }

        public queryEventsBySeverity(severity: AlertSeverity): SecurityEvent[] {
            return this.eventHistory.filter((evt) => evt.severity === severity);
        }

        public renderConsoleMetrics(): void {
            console.log("\n=======================================================");
            console.log("       SECURITY OPERATIONS CENTER - METRIC SUMMARY    ");
            console.log("=======================================================");
            console.log(`Total Events Processed : ${this.metrics.processedEvents}`);
            console.log(`Critical Alerts        : ${this.metrics.criticalAlertCount}`);
            console.log(`Unique Active Sources  : ${this.metrics.activeSources.size}`);
            console.log(`Telemetry Data Stream  : ${(this.metrics.bytesAnalyzed / 1024).toFixed(2)} KB`);
            console.log("=======================================================\n");
        }
    }
}

// System Demonstration
if (require.main === module) {
    const dashboard = new SecurityOperations.ThreatDashboardEngine();

    // Subscribe to specific alert types
    dashboard.subscribe("AUTHENTICATION_FAILURE", (evt) => {
        console.log(`[ALERT HANDLER] Auth Failure from IP: ${evt.sourceIp} | Severity: ${evt.severity}`);
    });

    dashboard.subscribe("*", (evt) => {
        if (evt.severity === SecurityOperations.AlertSeverity.CRITICAL) {
            console.log(`[CRITICAL TRAP] Event ID ${evt.id} requires immediate response!`);
        }
    });

    // Mock incoming telemetry events
    const sampleEvents = [
        JSON.stringify({
            id: "EVT-9001",
            timestamp: Date.now(),
            sourceIp: "192.168.1.105",
            eventType: "AUTHENTICATION_FAILURE",
            severity: "MEDIUM",
            payload: { user: "admin", attempt: 3 },
            tags: ["auth", "login"]
        }),
        JSON.stringify({
            id: "EVT-9002",
            timestamp: Date.now(),
            sourceIp: "10.0.0.50",
            eventType: "UNAUTHORIZED_PORT_SCAN",
            severity: "CRITICAL",
            payload: { portsScanned: [22, 80, 443, 8080] },
            tags: ["network", "scan"]
        })
    ];

    console.log("Ingesting Security Data Streams...");
    sampleEvents.forEach((payload) => dashboard.ingestRawPayload(payload));

    dashboard.renderConsoleMetrics();
}