import type { TrafficConversation } from "../../core/types";
import type { TrafficConversationWireDTO } from "../wire/trafficWireDtos";
import { asPlainObject } from "./mapperPrimitives";

export function asTrafficConversation(input: unknown): TrafficConversation | undefined {
  const payload: TrafficConversationWireDTO = asPlainObject(input) ?? {};
  const src = String(payload.src ?? "").trim();
  const dst = String(payload.dst ?? "").trim();

  if (!src || !dst) {
    return undefined;
  }

  return {
    src,
    dst,
    count: Number(payload.count ?? 0),
  };
}
