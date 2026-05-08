import type { Packet } from "../../core/types";
import { asPacket } from "../mappers/packetStreamMapper";

export type EventType = "packet" | "status" | "error";

export interface EventHandlers {
  packet?: (packet: Packet) => void;
  status?: (message: string) => void;
  error?: (message: string) => void;
}

type GetAuthToken = () => Promise<string>;

export interface EventClient {
  subscribeEvents(handlers: EventHandlers): () => void;
}

export function createEventClient(apiBase: string, getBackendAuthToken: GetAuthToken): EventClient {
  return {
    subscribeEvents(handlers: EventHandlers) {
      let disposed = false;
      let retryMs = 1000;
      let source: EventSource | null = null;
      let retryTimer: ReturnType<typeof setTimeout> | null = null;

      function connect() {
        if (disposed) return;

        void getBackendAuthToken()
          .then((token) => {
            if (disposed) return;
            const url = token
              ? `${apiBase}/api/events?access_token=${encodeURIComponent(token)}`
              : `${apiBase}/api/events`;
            source = new EventSource(url);

            source.addEventListener("ready", () => {
              retryMs = 1000;
            });

            source.addEventListener("packet", (event) => {
              try {
                handlers.packet?.(asPacket(JSON.parse((event as MessageEvent).data)));
              } catch {
                return;
              }
            });

            source.addEventListener("status", (event) => {
              try {
                const payload = JSON.parse((event as MessageEvent).data);
                handlers.status?.(String(payload.message ?? ""));
              } catch {
                return;
              }
            });

            source.addEventListener("error", (event) => {
              try {
                const payload = JSON.parse((event as MessageEvent).data);
                handlers.error?.(String(payload.message ?? ""));
              } catch {
                if (source) {
                  source.close();
                  source = null;
                }
                if (!disposed) {
                  handlers.error?.(`后端连接断开，${(retryMs / 1000).toFixed(0)}s 后重连...`);
                  retryTimer = setTimeout(() => {
                    retryMs = Math.min(retryMs * 2, 30000);
                    connect();
                  }, retryMs);
                }
              }
            });
          })
          .catch(() => {
            if (!disposed) {
              handlers.error?.("后端鉴权初始化失败");
            }
          });
      }

      connect();

      return () => {
        disposed = true;
        if (retryTimer) clearTimeout(retryTimer);
        if (source) source.close();
      };
    },
  };
}
