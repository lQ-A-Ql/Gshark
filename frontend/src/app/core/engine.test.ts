import { describe, expect, it } from "vitest";
import { buildProtocolTreeFromLayers } from "./engine";
import type { Packet } from "./types";

describe("buildProtocolTreeFromLayers", () => {
  it("assigns byte ranges to tshark layer nodes and descendants", () => {
    const packet: Packet = {
      id: 7,
      time: "12:00:00.000",
      src: "192.168.1.10",
      srcPort: 50000,
      dst: "10.0.0.5",
      dstPort: 80,
      proto: "TCP",
      displayProtocol: "HTTP",
      length: 98,
      info: "GET /index.html HTTP/1.1",
      payload: "47:45:54",
      ipHeaderLen: 20,
      l4HeaderLen: 20,
    };

    const tree = buildProtocolTreeFromLayers(
      {
        ip: { "ip.src": "192.168.1.10" },
        tcp: { "tcp.srcport": "50000" },
        http: { "http.request.method": "GET" },
      },
      packet,
    );

    const ipNode = tree.find((node) => node.label === "ip");
    const tcpNode = tree.find((node) => node.label === "tcp");
    const httpNode = tree.find((node) => node.label === "http");

    expect(ipNode?.byteRange).toEqual([14, 33]);
    expect(ipNode?.children?.[0]?.byteRange).toEqual([14, 33]);
    expect(tcpNode?.byteRange).toEqual([34, 53]);
    expect(httpNode?.byteRange).toEqual([54, 97]);
  });
});
