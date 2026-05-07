import { describe, expect, it } from "vitest";
import { asMediaAnalysis } from "./mediaMapper";

describe("mediaMapper", () => {
  it("maps media sessions and artifacts", () => {
    const result = asMediaAnalysis({
      total_media_packets: 7,
      protocols: [{ label: "RTP", count: 4 }],
      applications: [{ label: "SIP", count: 2 }],
      sessions: [
        {
          id: "rtp-1",
          media_type: "audio",
          family: "rtp",
          application: "SIP",
          source: "10.0.0.1",
          source_port: 10000,
          destination: "10.0.0.2",
          destination_port: 10002,
          transport: "UDP",
          ssrc: "1234",
          payload_type: "0",
          codec: "PCMU",
          clock_rate: 8000,
          start_time: "0.1",
          end_time: "1.0",
          packet_count: 4,
          gap_count: 1,
          control_summary: "rtcp seen",
          tags: ["audio", 7],
          notes: ["gap"],
          artifact: {
            token: "tok",
            name: "call.wav",
            codec: "pcm",
            format: "wav",
            size_bytes: 2048,
          },
        },
      ],
      notes: ["media note"],
    });

    expect(result.totalMediaPackets).toBe(7);
    expect(result.protocols).toEqual([{ label: "RTP", count: 4 }]);
    expect(result.sessions[0]).toMatchObject({
      id: "rtp-1",
      mediaType: "audio",
      sourcePort: 10000,
      destinationPort: 10002,
      tags: ["audio", "7"],
      notes: ["gap"],
      artifact: {
        token: "tok",
        name: "call.wav",
        sizeBytes: 2048,
      },
    });
    expect(result.notes).toEqual(["media note"]);
  });

  it("returns empty defaults for missing sections", () => {
    const result = asMediaAnalysis({});
    expect(result.sessions).toEqual([]);
    expect(result.protocols).toEqual([]);
    expect(result.notes).toEqual([]);
  });
});
