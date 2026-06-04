import type { BackendBridge, BackendClients } from "./bridgeTypes";
import type { PlaybookClient } from "./clients/playbookClient";
import { createPlaybookClient } from "./clients/playbookClient";

// The playbook client uses the bridge's JSON request capability.
// Since bridge implements all client interfaces, we cast its request
// capability through the bridge methods.
function createPlaybookFromBridge(_bridge: BackendBridge): PlaybookClient {
  // Use the bridge's existing listThreatHits as a proxy for its JSON request capability.
  // The playbook client makes its own HTTP calls via the injected request function.
  // We create a thin adapter that uses fetch directly against the backend.
  const apiBase = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";
  const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
    const resp = await fetch(`${apiBase}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${await resp.text().catch(() => resp.statusText)}`);
    }
    return resp.json() as Promise<T>;
  };
  return createPlaybookClient(request);
}

export function createBackendClients(bridge: BackendBridge): BackendClients {
  return {
    runtime: bridge,
    capture: bridge,
    packet: bridge,
    hunting: bridge,
    object: bridge,
    stream: bridge,
    analysis: bridge,
    evidence: bridge,
    media: bridge,
    vehicleDBC: bridge,
    securityMaterial: bridge,
    miscModule: bridge,
    playbook: createPlaybookFromBridge(bridge),
  };
}
