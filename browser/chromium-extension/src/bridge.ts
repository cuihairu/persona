export interface BridgeProbeResponse {
    status?: string;
    version?: string;
    activeIdentity?: string;
    unlocked?: boolean;
}

export interface BridgeStatus {
    connected: boolean;
    endpoint: string;
    lastChecked: number;
    message?: string;
    payload?: BridgeProbeResponse;
}

const DEFAULT_ENDPOINT = 'http://127.0.0.1:19945/status';

/**
 * Attempt to reach the Persona desktop/CLI bridge HTTP endpoint.
 * The CLI can expose this endpoint via `persona serve --bridge` (future),
 * so for now we optimistically probe and surface errors to the popup UI.
 */
export async function pingBridge(endpoint = DEFAULT_ENDPOINT): Promise<BridgeStatus> {
    const now = Date.now();
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 1500);
        const response = await fetch(endpoint, {
            headers: {
                Accept: 'application/json'
            },
            signal: controller.signal
        });
        clearTimeout(timeout);

        if (!response.ok) {
            return {
                connected: false,
                endpoint,
                lastChecked: now,
                message: `Bridge responded with ${response.status}`
            };
        }

        const payload = (await response.json()) as BridgeProbeResponse;
        return {
            connected: true,
            endpoint,
            lastChecked: now,
            message: payload?.status ?? 'Bridge online',
            payload
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return {
            connected: false,
            endpoint,
            lastChecked: now,
            message
        };
    }
}
