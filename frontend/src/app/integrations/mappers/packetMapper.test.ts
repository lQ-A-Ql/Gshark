import { describe, expect, it } from "vitest";
import { asPacket } from "./packetMapper";

describe("asPacket", () => {
  it("normalizes packet and color-feature wire fields", () => {
    const packet = asPacket({
      id: 7,
      timestamp: "2026-05-14T01:02:03.456Z",
      source_ip: "10.0.0.1",
      source_port: 12345,
      dest_ip: "10.0.0.2",
      dest_port: 443,
      protocol: "TCP",
      display_protocol: " TLS ",
      length: 128,
      info: "Client Hello",
      payload: "hello",
      raw_hex: "68656c6c6f",
      stream_id: 9,
      ip_header_len: 20,
      l4_header_len: 32,
      color_features: {
        tcp_syn: true,
        tcp_fin: false,
        hsrp_state: 2,
        ipv4_ttl: 64,
        has_smb: true,
      },
    });

    expect(packet).toMatchObject({
      id: 7,
      time: "01:02:03.456",
      src: "10.0.0.1",
      srcPort: 12345,
      dst: "10.0.0.2",
      dstPort: 443,
      proto: "TCP",
      displayProtocol: "TLS",
      length: 128,
      info: "Client Hello",
      payload: "hello",
      rawHex: "68656c6c6f",
      streamId: 9,
      ipHeaderLen: 20,
      l4HeaderLen: 32,
    });
    expect(packet.colorFeatures).toMatchObject({
      tcpSyn: true,
      tcpFin: false,
      hsrpState: 2,
      ipv4Ttl: 64,
      hasSmb: true,
    });
  });
});
