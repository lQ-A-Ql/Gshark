import type { BackendBridge } from "./bridgeTypes";
import type { PlaybookClient } from "./clients/playbookClient";
import { createPlaybookClient } from "./clients/playbookClient";

export function createPlaybookFromBridge(_bridge: BackendBridge): PlaybookClient {
  const apiBase = (import.meta.env.VITE_BACKEND_URL as string | undefined) ?? "http://127.0.0.1:17891";
  const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
    const resp = await fetch(`${apiBase}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${await resp.text().catch(() => resp.statusText)}`);
    return resp.json() as Promise<T>;
  };
  return createPlaybookClient(request);
}
