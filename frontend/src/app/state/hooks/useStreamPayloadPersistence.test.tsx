import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../../core/types";
import { EMPTY_BINARY_STREAM, EMPTY_HTTP_STREAM } from "../streamState";
import { useStreamPayloadPersistence } from "./useStreamPayloadPersistence";

describe("useStreamPayloadPersistence", () => {
  it("persists backend payload updates and patches active HTTP stream", async () => {
    const updateStreamPayloads = vi.fn(async () => undefined);
    const { result } = renderHook(() => {
      const httpCacheRef = useRef(new Map<number, HttpStream>());
      const tcpCacheRef = useRef(new Map<number, BinaryStream>());
      const udpCacheRef = useRef(new Map<number, BinaryStream>());
      const [httpStream, setHttpStream] = useState<HttpStream>({
        ...EMPTY_HTTP_STREAM,
        id: 7,
        chunks: [{ packetId: 1, direction: "server", body: "old" }],
      });
      const [tcpStream, setTcpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
      const [udpStream, setUdpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
      const persistStreamPayloads = useStreamPayloadPersistence({
        backendConnected: true,
        httpCacheRef,
        setHttpStream,
        setTcpStream,
        setUdpStream,
        tcpCacheRef,
        udpCacheRef,
        updateStreamPayloads,
      });
      return { httpStream, persistStreamPayloads, tcpStream, udpStream };
    });

    await act(async () => {
      await result.current.persistStreamPayloads("HTTP", 7, [{ index: 0, body: "new" }]);
    });

    expect(updateStreamPayloads).toHaveBeenCalledWith("HTTP", 7, [{ index: 0, body: "new" }]);
    expect(result.current.httpStream.chunks[0]?.body).toBe("new");
  });
});
