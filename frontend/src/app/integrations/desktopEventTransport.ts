import type { EventHandlers } from "./clients/eventClient";
import { asPacket } from "./mappers/packetStreamMapper";
import { EventsOn } from "../../../wailsjs/runtime";

export function subscribeDesktopEvents(handlers: EventHandlers): () => void {
  const cleanups = [
    EventsOn("meow:backend:packet", (payload) => {
      handlers.packet?.(asPacket(payload));
    }),
    EventsOn("meow:backend:status", (payload) => {
      handlers.status?.(String((payload as { message?: unknown })?.message ?? payload ?? ""));
    }),
    EventsOn("meow:backend:error", (payload) => {
      handlers.error?.(String((payload as { message?: unknown })?.message ?? payload ?? ""));
    }),
  ];
  return () => {
    for (const cleanup of cleanups) {
      cleanup();
    }
  };
}
