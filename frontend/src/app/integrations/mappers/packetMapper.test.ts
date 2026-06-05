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
      tls_fingerprint: {
        ja3_hash: "72a589da586844d7f0818ce684948eea",
        ja3s_hash: "b742b407517bac9536a77a7b0fee28e9",
        ja3_raw: "771,4865-4866,0-23-65281,29-23-24,0",
      },
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
      tlsFingerprint: {
        ja3Hash: "72a589da586844d7f0818ce684948eea",
        ja3sHash: "b742b407517bac9536a77a7b0fee28e9",
        ja3Raw: "771,4865-4866,0-23-65281,29-23-24,0",
      },
    });
    expect(packet.colorFeatures).toMatchObject({
      tcpSyn: true,
      tcpFin: false,
      hsrpState: 2,
      ipv4Ttl: 64,
      hasSmb: true,
    });
  });

  it("omits empty tls fingerprint fields", () => {
    const packet = asPacket({
      id: 8,
      protocol: "TLS",
      tls_fingerprint: {
        ja3_hash: "   ",
        ja3s_hash: "",
      },
    });

    expect(packet.tlsFingerprint).toBeUndefined();
  });
});
