import { startTransition, useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { BinaryStream, HttpStream, StreamProtocol } from "../../core/types";
import { persistStreamPayloadsState } from "../streamPayloadPersist";

type StreamPatch = { index: number; body: string };

interface UseStreamPayloadPersistenceOptions {
  readonly backendConnected: boolean;
  readonly httpCacheRef: MutableRefObject<Map<number, HttpStream>>;
  readonly setHttpStream: Dispatch<SetStateAction<HttpStream>>;
  readonly setTcpStream: Dispatch<SetStateAction<BinaryStream>>;
  readonly setUdpStream: Dispatch<SetStateAction<BinaryStream>>;
  readonly tcpCacheRef: MutableRefObject<Map<number, BinaryStream>>;
  readonly udpCacheRef: MutableRefObject<Map<number, BinaryStream>>;
  readonly updateStreamPayloads: (
    protocol: StreamProtocol,
    streamId: number,
    patches: StreamPatch[],
  ) => Promise<unknown>;
}

export function useStreamPayloadPersistence(options: UseStreamPayloadPersistenceOptions) {
  return useCallback(
    async (protocol: StreamProtocol, streamId: number, patches: StreamPatch[]) => {
      await persistStreamPayloadsState({
        protocol,
        streamId,
        patches,
        backendConnected: options.backendConnected,
        updateStreamPayloads: options.updateStreamPayloads,
        startTransition,
        setHttpStream: options.setHttpStream,
        setTcpStream: options.setTcpStream,
        setUdpStream: options.setUdpStream,
        httpCache: options.httpCacheRef.current,
        tcpCache: options.tcpCacheRef.current,
        udpCache: options.udpCacheRef.current,
      });
    },
    [options],
  );
}
