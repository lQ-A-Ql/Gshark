import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { createEventClient, type EventHandlers } from "./eventClient";

function createReadableStream(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let index = 0;
  return new ReadableStream({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(encoder.encode(chunks[index]));
        index++;
      } else {
        controller.close();
      }
    },
  });
}

function createMockResponse(chunks: string[]): Response {
  return {
    ok: true,
    status: 200,
    body: createReadableStream(chunks),
  } as unknown as Response;
}

describe("createEventClient", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue(createMockResponse([]));
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    vi.unstubAllGlobals();
  });

  it("sends the token in the Authorization header and not in the URL", async () => {
    const client = createEventClient("http://127.0.0.1:17891", () => Promise.resolve("secret-token"));
    const unsubscribe = client.subscribeEvents({});

    // Allow the async connect() flow to start and call fetch.
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:17891/api/events");
    expect((url as string).includes("access_token")).toBe(false);
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: "Bearer secret-token",
      Accept: "text/event-stream",
    });

    unsubscribe();
  });

  it("dispatches packet, status, error and ready events", async () => {
    fetchSpy.mockResolvedValue(
      createMockResponse([
        "event: ready\ndata: {}\n\n",
        'event: packet\ndata: {"id":1}\n\n',
        'event: status\ndata: {"message":"ok"}\n\n',
        'event: error\ndata: {"message":"boom"}\n\n',
      ]),
    );

    const handlers: EventHandlers = {
      packet: vi.fn(),
      status: vi.fn(),
      error: vi.fn(),
    };

    const client = createEventClient("http://127.0.0.1:17891", () => Promise.resolve("token"));
    const unsubscribe = client.subscribeEvents(handlers);

    // Wait for all chunks to be processed and the stream to close.
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(handlers.packet).toHaveBeenCalledTimes(1);
    expect(handlers.status).toHaveBeenCalledWith("ok");
    expect(handlers.error).toHaveBeenCalledWith("boom");

    unsubscribe();
  });
});
