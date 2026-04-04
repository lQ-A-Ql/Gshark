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

    const ipNode = tree.find((node) => node.label.startsWith("Internet Protocol Version 4"));
    const tcpNode = tree.find((node) => node.label.startsWith("Transmission Control Protocol"));
    const httpNode = tree.find((node) => node.label.startsWith("Hypertext Transfer Protocol"));

    expect(ipNode?.byteRange).toEqual([14, 33]);
    expect(ipNode?.children?.[0]?.byteRange).toEqual([14, 33]);
    expect(tcpNode?.byteRange).toEqual([34, 53]);
    expect(httpNode?.byteRange).toEqual([54, 97]);
  });

  it("orders layers using frame protocols like wireshark", () => {
    const tree = buildProtocolTreeFromLayers(
      {
        tcp: { "tcp.srcport": "50000" },
        http: { "http.request.method": "GET" },
        frame: { frame_frame_protocols: "eth:ip:tcp:http", frame_frame_number: "7", frame_frame_len: "98", frame_frame_cap_len: "98" },
        ip: { "ip.src": "192.168.1.10", "ip.dst": "10.0.0.5" },
        eth: { "eth.src": "00:11:22:33:44:55", "eth.dst": "66:77:88:99:aa:bb" },
      },
      null,
    );

    expect(tree.map((node) => node.label)).toEqual([
      "Frame 7: 98 bytes on wire (784 bits), 98 bytes captured (784 bits)",
      "Ethernet II, Src: 00:11:22:33:44:55, Dst: 66:77:88:99:aa:bb",
      "Internet Protocol Version 4, Src: 192.168.1.10, Dst: 10.0.0.5",
      "Transmission Control Protocol, Src Port: 50000, Dst Port: ?",
      "Hypertext Transfer Protocol: GET",
    ]);
  });
});
