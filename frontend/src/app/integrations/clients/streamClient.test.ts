import { describe, expect, it, vi } from "vitest";
import { createStreamClient } from "./streamClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("streamClient packet resource methods", () => {
  it("maps stream indexes and preserves abort signals", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/index?protocol=TCP");
      expect(init?.signal).toBe(signal);
      return { ids: ["3", 1, -1, "bad", 2] };
    }) as unknown as JsonRequest;

    await expect(createStreamClient(request).listStreamIds("TCP", signal)).resolves.toEqual([1, 2, 3]);
  });

  it("maps HTTP stream payloads and preserves abort signals", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/http?streamId=7");
      expect(init?.signal).toBe(signal);
      return { stream_id: 7, from: "client", to: "server", request: "GET /", response: "OK" };
    }) as unknown as JsonRequest;

    await expect(createStreamClient(request).getHttpStream(7, signal)).resolves.toMatchObject({
      id: 7,
      client: "client",
      server: "server",
      request: "GET /",
      response: "OK",
      chunks: [
        { packetId: 0, direction: "client", body: "GET /" },
        { packetId: 0, direction: "server", body: "OK" },
      ],
    });
  });

  it("maps raw stream payloads and raw stream pages", async () => {
    const signal = new AbortController().signal;
    const requestMock = vi
      .fn()
      .mockResolvedValueOnce({
        stream_id: 9,
        from: "10.0.0.1",
        to: "10.0.0.2",
        chunks: [{ packet_id: 1, direction: "server", body: "ff" }],
        next_cursor: 1,
        total: 1,
        has_more: false,
      })
      .mockResolvedValueOnce({
        stream_id: 10,
        from: "10.0.0.3",
        to: "10.0.0.4",
        chunks: [{ packet_id: 3, direction: "client", body: "aa" }],
        next_cursor: 8,
        total: 9,
        has_more: true,
      });
    const request = requestMock as unknown as JsonRequest;
    const client = createStreamClient(request);

    await expect(client.getRawStream("UDP", 9, signal)).resolves.toMatchObject({
      id: 9,
      protocol: "UDP",
      from: "10.0.0.1",
      to: "10.0.0.2",
      chunks: [{ packetId: 1, direction: "server", body: "ff" }],
      nextCursor: 1,
      totalChunks: 1,
      hasMore: false,
    });
    await expect(client.getRawStreamPage("TCP", 10, 3, 5, signal)).resolves.toMatchObject({
      id: 10,
      protocol: "TCP",
      from: "10.0.0.3",
      to: "10.0.0.4",
      chunks: [{ packetId: 3, direction: "client", body: "aa" }],
      nextCursor: 8,
      totalChunks: 9,
      hasMore: true,
    });
    expect(requestMock).toHaveBeenNthCalledWith(1, "/api/streams/raw?protocol=UDP&streamId=9", { signal });
    expect(requestMock).toHaveBeenNthCalledWith(2, "/api/streams/raw/page?protocol=TCP&streamId=10&cursor=3&limit=5", {
      signal,
    });
  });

  it("posts payload updates and maps protocol-specific stream shapes", async () => {
    const request = vi.fn().mockImplementation(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/payloads");
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      if (body.protocol === "HTTP") {
        expect(body).toMatchObject({
          protocol: "HTTP",
          stream_id: 11,
          patches: [{ index: 0, body: "GET /login" }],
        });
        return { stream_id: 11, from: "client", to: "server", request: "GET /login", response: "200 OK" };
      }
      expect(body).toMatchObject({
        protocol: "TCP",
        stream_id: 12,
        patches: [{ index: 0, body: "aa" }],
      });
      return {
        stream_id: 12,
        from: "10.0.0.5",
        to: "10.0.0.6",
        chunks: [{ packet_id: 4, direction: "client", body: "aa" }],
        next_cursor: 1,
        total: 1,
        has_more: false,
      };
    }) as unknown as JsonRequest;
    const client = createStreamClient(request);

    await expect(client.updateStreamPayloads("HTTP", 11, [{ index: 0, body: "GET /login" }])).resolves.toMatchObject({
      id: 11,
      client: "client",
      server: "server",
      request: "GET /login",
      response: "200 OK",
    });
    await expect(client.updateStreamPayloads("TCP", 12, [{ index: 0, body: "aa" }])).resolves.toMatchObject({
      id: 12,
      protocol: "TCP",
      from: "10.0.0.5",
      to: "10.0.0.6",
      chunks: [{ packetId: 4, direction: "client", body: "aa" }],
      nextCursor: 1,
      totalChunks: 1,
      hasMore: false,
    });
  });

  it("posts decode requests and maps decoder result payloads", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/decode");
      expect(init?.method).toBe("POST");
      expect(init?.signal).toBe(signal);
      expect(JSON.parse(String(init?.body ?? "{}"))).toEqual({
        decoder: "base64",
        payload: "SGVsbG8=",
        options: { charset: "utf-8" },
      });
      return {
        decoder: "base64",
        summary: "decoded",
        text: "Hello",
        bytes_hex: "48656c6c6f",
        encoding: "utf-8",
        confidence: 88,
        warnings: ["short"],
        signals: ["ascii"],
        attempt_errors: ["fallback skipped"],
      };
    }) as unknown as JsonRequest;

    await expect(
      createStreamClient(request).decodeStreamPayload("base64", "SGVsbG8=", { charset: "utf-8" }, signal),
    ).resolves.toEqual({
      decoder: "base64",
      summary: "decoded",
      text: "Hello",
      bytesHex: "48656c6c6f",
      encoding: "utf-8",
      confidence: 88,
      warnings: ["short"],
      signals: ["ascii"],
      attemptErrors: ["fallback skipped"],
    });
  });

  it("posts inspect requests and maps candidate payloads", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/inspect");
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body ?? "{}"))).toEqual({ payload: "cmd=whoami" });
      return {
        normalized_payload: "cmd=whoami",
        candidates: [
          {
            id: "query:cmd",
            label: "cmd",
            kind: "parameter",
            param_name: "cmd",
            value: "whoami",
            preview: "whoami",
            confidence: 92,
            decoder_hints: ["base64"],
            fingerprints: ["command"],
            family_hint: "antsword",
            decoder_options_hint: { mode: "strict" },
            source_role: "request",
          },
          "bad",
        ],
        suggested_candidate_id: "query:cmd",
        suggested_decoder: "base64",
        suggested_family: "antsword",
        confidence: 92,
        reasons: ["parameter command"],
      };
    }) as unknown as JsonRequest;

    await expect(createStreamClient(request).inspectStreamPayload("cmd=whoami")).resolves.toMatchObject({
      normalizedPayload: "cmd=whoami",
      candidates: [
        {
          id: "query:cmd",
          label: "cmd",
          kind: "parameter",
          paramName: "cmd",
          value: "whoami",
          preview: "whoami",
          confidence: 92,
          decoderHints: ["base64"],
          fingerprints: ["command"],
          familyHint: "antsword",
          decoderOptionsHint: { mode: "strict" },
          sourceRole: "request",
        },
        { id: "", label: "", kind: "", value: "", decoderHints: [], fingerprints: [] },
      ],
      suggestedCandidateId: "query:cmd",
      suggestedDecoder: "base64",
      suggestedFamily: "antsword",
      confidence: 92,
      reasons: ["parameter command"],
    });
  });

  it("maps stream payload sources with source metadata", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/streams/payload-sources?limit=25");
      expect(init?.signal).toBe(signal);
      return [
        {
          id: "source-1",
          method: "POST",
          host: "example.test",
          uri: "/shell.php",
          packet_id: 42,
          stream_id: 7,
          source_type: "http_param",
          param_name: "cmd",
          payload: "whoami",
          preview: "whoami",
          confidence: 90,
          signals: ["command"],
          decoder_hints: ["base64"],
          family_hint: "antsword",
          decoder_options_hint: { key: "value" },
          source_role: "request",
          content_type: "application/x-www-form-urlencoded",
          occurrence_count: 3,
          first_time: "2026-05-14T00:00:00Z",
          last_time: "2026-05-14T00:00:03Z",
          repeat_window_seconds: 3,
          related_packets: [42, "43", 0],
          rule_reasons: ["repeat burst"],
        },
      ];
    }) as unknown as JsonRequest;

    await expect(createStreamClient(request).listStreamPayloadSources(signal, 25)).resolves.toEqual([
      {
        id: "source-1",
        method: "POST",
        host: "example.test",
        uri: "/shell.php",
        packetId: 42,
        streamId: 7,
        sourceType: "http_param",
        paramName: "cmd",
        payload: "whoami",
        preview: "whoami",
        confidence: 90,
        signals: ["command"],
        decoderHints: ["base64"],
        familyHint: "antsword",
        decoderOptionsHint: { key: "value" },
        sourceRole: "request",
        contentType: "application/x-www-form-urlencoded",
        occurrenceCount: 3,
        firstTime: "2026-05-14T00:00:00Z",
        lastTime: "2026-05-14T00:00:03Z",
        repeatWindowSeconds: 3,
        relatedPackets: [42, 43],
        ruleReasons: ["repeat burst"],
      },
    ]);
  });

  it("maps packet raw hex payloads and packet layers", async () => {
    const signal = new AbortController().signal;
    const requestMock = vi
      .fn()
      .mockResolvedValueOnce({ raw_hex: "de ad be ef" })
      .mockResolvedValueOnce({ layers: { frame: { frame_number: "42" }, tcp: {} } })
      .mockResolvedValueOnce({ layers: ["bad"] });
    const request = requestMock as unknown as JsonRequest;
    const client = createStreamClient(request);

    await expect(client.getPacketRawHex(42, signal)).resolves.toBe("de ad be ef");
    await expect(client.getPacketLayers(42, signal)).resolves.toEqual({ frame: { frame_number: "42" }, tcp: {} });
    await expect(client.getPacketLayers(43, signal)).resolves.toBeNull();
    expect(requestMock).toHaveBeenNthCalledWith(1, "/api/packet/raw?id=42", { signal });
    expect(requestMock).toHaveBeenNthCalledWith(2, "/api/packet/layers?id=42", { signal });
    expect(requestMock).toHaveBeenNthCalledWith(3, "/api/packet/layers?id=43", { signal });
  });
});
