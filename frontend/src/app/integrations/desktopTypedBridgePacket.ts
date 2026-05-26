import type { PacketLocateResult } from "./clients/captureClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { typedCall } from "./desktopTypedBridgeCore";
import { asPlainObject } from "./mappers/mapperPrimitives";
import { asPacket } from "./mappers/packetStreamMapper";

export function createPacketTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async locatePacketPage(packetId, limit, filter = "", signal) {
      return asPacketLocateResult(
        await typedCall(
          () => desktopApp.LocatePacketPage!(packetId, limit, filter),
          "DesktopApp.LocatePacketPage",
          signal,
        ),
        packetId,
      );
    },
    async getPacket(packetId, signal) {
      return asPacket(await typedCall(() => desktopApp.GetPacket!(packetId), "DesktopApp.GetPacket", signal));
    },
  };
}

function asPacketLocateResult(input: unknown, packetId: number): PacketLocateResult {
  const payload = asPlainObject(input);
  return {
    packetId: Number(payload?.packet_id ?? packetId),
    cursor: Number(payload?.cursor ?? 0),
    total: Number(payload?.total ?? 0),
    found: Boolean(payload?.found),
  };
}
