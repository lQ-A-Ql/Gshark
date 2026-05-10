import type { Packet } from "../core/types";
import { resolvePacketStreamProtocol, type StreamDisplayProtocol } from "./streamProtocol";
import type { PreparedPacketStream } from "./sentinelTypes";

interface PreparePacketStreamOptions {
  readonly packetId: number;
  readonly preferredProtocol?: StreamDisplayProtocol;
  readonly filterOverride?: string;
  readonly locatePacketById: (packetId: number, filterOverride?: string) => Promise<Packet | null>;
  readonly setActiveStream: (protocol: StreamDisplayProtocol, streamId: number) => Promise<void>;
}

export async function preparePacketStreamState({
  packetId,
  preferredProtocol,
  filterOverride,
  locatePacketById,
  setActiveStream,
}: PreparePacketStreamOptions): Promise<PreparedPacketStream> {
  const packet = await locatePacketById(packetId, filterOverride);
  if (!packet || packet.streamId == null || packet.streamId < 0) {
    return { packet, protocol: null, streamId: null };
  }

  const protocol = resolvePacketStreamProtocol(packet.proto, preferredProtocol ?? null);
  await setActiveStream(protocol, packet.streamId);
  return {
    packet,
    protocol,
    streamId: packet.streamId,
  };
}
