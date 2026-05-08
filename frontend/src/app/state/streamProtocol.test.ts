import { describe, expect, it } from "vitest";
import { resolvePacketStreamProtocol } from "./streamProtocol";

describe("streamProtocol helpers", () => {
  it("keeps preferred stream protocol when provided", () => {
    expect(resolvePacketStreamProtocol("HTTP", "TCP")).toBe("TCP");
    expect(resolvePacketStreamProtocol("UDP", "HTTP")).toBe("HTTP");
  });

  it("maps packet protocol to stream protocol by default", () => {
    expect(resolvePacketStreamProtocol("HTTP")).toBe("HTTP");
    expect(resolvePacketStreamProtocol("UDP")).toBe("UDP");
    expect(resolvePacketStreamProtocol("TLS")).toBe("TCP");
    expect(resolvePacketStreamProtocol("DNS")).toBe("TCP");
  });
});
