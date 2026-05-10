import { useCallback } from "react";
import type { Packet } from "../../core/types";
import { preparePacketStreamState } from "../packetStreamPrepare";
import type { PreparedPacketStream } from "../sentinelTypes";
import type { StreamDisplayProtocol } from "../streamProtocol";

interface UsePreparePacketStreamOptions {
  readonly locatePacketById: (packetId: number, filterOverride?: string) => Promise<Packet | null>;
  readonly setActiveStream: (protocol: StreamDisplayProtocol, streamId: number) => Promise<void>;
}

export function usePreparePacketStream(options: UsePreparePacketStreamOptions) {
  return useCallback(
    async (
      packetId: number,
      preferredProtocol?: StreamDisplayProtocol,
      filterOverride?: string,
    ): Promise<PreparedPacketStream> => {
      return preparePacketStreamState({
        packetId,
        preferredProtocol,
        filterOverride,
        locatePacketById: options.locatePacketById,
        setActiveStream: options.setActiveStream,
      });
    },
    [options],
  );
}
