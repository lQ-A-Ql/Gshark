import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { createStreamSwitchSequences } from "../streamSwitchSequence";
import { useActiveStreamSwitch } from "./useActiveStreamSwitch";

const httpStream = (id: number): HttpStream => ({
  id,
  client: "c",
  server: "s",
  request: "",
  response: "",
  chunks: [],
});
const rawStream = (protocol: "TCP" | "UDP", id: number): BinaryStream => ({
  id,
  protocol,
  from: "a",
  to: "b",
  chunks: [],
  nextCursor: 0,
  totalChunks: 0,
  hasMore: false,
});

describe("useActiveStreamSwitch", () => {
  it("binds stream switch workflow to provider caches, setters, metrics, and bridge fetchers", async () => {
    const fetchHttpStream = vi.fn(async (id: number) => httpStream(id));
    const fetchRawStreamPage = vi.fn(async (protocol: "TCP" | "UDP", id: number) => rawStream(protocol, id));
    const prefetchAdjacentStreams = vi.fn();
    const recordStreamSwitchMetric = vi.fn();
    const { result } = renderHook(() => {
      const [backendStatus, setBackendStatus] = useState("");
      const [http, setHttpStream] = useState<HttpStream>(httpStream(-1));
      const [tcp, setTcpStream] = useState<BinaryStream>(rawStream("TCP", -1));
      const [udp, setUdpStream] = useState<BinaryStream>(rawStream("UDP", -1));
      const setActiveStream = useActiveStreamSwitch({
        activeCapturePathRef: useRef("sample.pcapng"),
        backendConnected: true,
        captureTaskScopeRef: useRef(createCaptureTaskScope()),
        fetchHttpStream,
        fetchRawStreamPage,
        httpCacheRef: useRef(new Map<number, HttpStream>()),
        prefetchAdjacentStreams,
        recordStreamSwitchMetric,
        setBackendStatus,
        setHttpStream,
        setTcpStream,
        setUdpStream,
        streamSwitchSequencesRef: useRef(createStreamSwitchSequences()),
        tcpCacheRef: useRef(new Map<number, BinaryStream>()),
        udpCacheRef: useRef(new Map<number, BinaryStream>()),
      });
      return { backendStatus, http, setActiveStream, tcp, udp };
    });

    await act(async () => {
      await result.current.setActiveStream("TCP", 12);
    });

    expect(fetchRawStreamPage).toHaveBeenCalledWith("TCP", 12, 0, 96, expect.any(AbortSignal));
    expect(result.current.tcp).toMatchObject({ id: 12, protocol: "TCP" });
    expect(result.current.http.id).toBe(-1);
    expect(result.current.udp.id).toBe(-1);
    expect(recordStreamSwitchMetric).toHaveBeenCalledWith("TCP", expect.any(Number), false);
    expect(prefetchAdjacentStreams).toHaveBeenCalledWith("TCP", 12);
    expect(result.current.backendStatus).toBe("");
  });
});
