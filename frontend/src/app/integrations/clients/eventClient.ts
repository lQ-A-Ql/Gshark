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

interface SSEMessage {
  event: string;
  data: string;
}

function parseSSEMessages(chunk: string, bufferRef: { value: string }): SSEMessage[] {
  bufferRef.value += chunk;
  const messages: SSEMessage[] = [];
  let currentEvent = "";
  let currentData = "";

  const flushMessage = () => {
    if (currentData !== "" || currentEvent !== "") {
      messages.push({ event: currentEvent || "message", data: currentData });
      currentEvent = "";
      currentData = "";
    }
  };

  while (bufferRef.value.length > 0) {
    const newlineIndex = bufferRef.value.indexOf("\n");
    if (newlineIndex < 0) {
      break;
    }
    let line = bufferRef.value.slice(0, newlineIndex);
    bufferRef.value = bufferRef.value.slice(newlineIndex + 1);

    // Strip trailing \r for CRLF line endings.
    if (line.endsWith("\r")) {
      line = line.slice(0, -1);
    }

    if (line === "") {
      flushMessage();
      continue;
    }

    const colonIndex = line.indexOf(":");
    let field: string;
    let value: string;
    if (colonIndex < 0) {
      field = line;
      value = "";
    } else {
      field = line.slice(0, colonIndex);
      value = line.slice(colonIndex + 1);
      if (value.startsWith(" ")) {
        value = value.slice(1);
      }
    }

    switch (field) {
      case "event":
        currentEvent = value;
        break;
      case "data":
        if (currentData !== "") {
          currentData += "\n";
        }
        currentData += value;
        break;
      case "id":
      case "retry":
        // Ignored for now; retry timing is handled client-side.
        break;
      default:
        // Unknown fields are ignored per the SSE spec.
        break;
    }
  }

  // Do not flush a partially-received message; wait for the terminating empty line.
  return messages;
}

export function createEventClient(apiBase: string, getBackendAuthToken: GetAuthToken): EventClient {
  return {
    subscribeEvents(handlers: EventHandlers) {
      let disposed = false;
      let retryMs = 1000;
      let abortController: AbortController | null = null;
      let retryTimer: ReturnType<typeof setTimeout> | null = null;
      const bufferRef = { value: "" };

      function scheduleReconnect() {
        if (disposed) return;
        handlers.error?.(`后端连接断开，${(retryMs / 1000).toFixed(0)}s 后重连...`);
        retryTimer = setTimeout(() => {
          retryMs = Math.min(retryMs * 2, 30000);
          connect();
        }, retryMs);
      }

      function dispatchMessage(message: SSEMessage) {
        try {
          switch (message.event) {
            case "ready":
              retryMs = 1000;
              break;
            case "packet":
              handlers.packet?.(asPacket(JSON.parse(message.data)));
              break;
            case "status": {
              const payload = JSON.parse(message.data);
              handlers.status?.(String(payload.message ?? ""));
              break;
            }
            case "error": {
              const payload = JSON.parse(message.data);
              handlers.error?.(String(payload.message ?? ""));
              break;
            }
          }
        } catch {
          // Ignore malformed events.
        }
      }

      async function connect() {
        if (disposed) return;
        abortController = new AbortController();

        try {
          const token = await getBackendAuthToken();
          if (disposed) return;

          const headers: Record<string, string> = {
            Accept: "text/event-stream",
          };
          if (token) {
            headers.Authorization = `Bearer ${token}`;
          }

          const response = await fetch(`${apiBase}/api/events`, {
            method: "GET",
            headers,
            signal: abortController.signal,
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }

          const reader = response.body?.getReader();
          if (!reader) {
            throw new Error("response body missing");
          }

          const decoder = new TextDecoder();
          while (!disposed) {
            const { done, value } = await reader.read();
            if (done) {
              break;
            }
            const chunk = decoder.decode(value, { stream: true });
            const messages = parseSSEMessages(chunk, bufferRef);
            for (const message of messages) {
              dispatchMessage(message);
            }
          }

          if (!disposed) {
            scheduleReconnect();
          }
        } catch {
          if (disposed) return;
          scheduleReconnect();
        }
      }

      connect();

      return () => {
        disposed = true;
        if (retryTimer) clearTimeout(retryTimer);
        abortController?.abort();
      };
    },
  };
}
