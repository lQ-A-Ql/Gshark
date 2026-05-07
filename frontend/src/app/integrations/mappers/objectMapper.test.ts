import { describe, expect, it } from "vitest";
import { asObject, asObjectList } from "./objectMapper";

describe("objectMapper", () => {
  it("maps extracted objects and keeps only HTTP/FTP source values", () => {
    expect(
      asObject({
        id: 3,
        packet_id: 42,
        name: "invoice.txt",
        size_bytes: 128,
        mime: "text/plain",
        magic: "MZ executable",
        source: "FTP",
      }),
    ).toEqual({
      id: 3,
      packetId: 42,
      name: "invoice.txt",
      sizeBytes: 128,
      mime: "text/plain",
      magic: "MZ executable",
      source: "FTP",
    });

    expect(asObject({ source: "SMTP" }).source).toBe("HTTP");
  });

  it("maps arrays defensively", () => {
    expect(asObjectList([{ id: 1 }, { id: 2, source: "FTP" }])).toHaveLength(2);
    expect(asObjectList(null)).toEqual([]);
  });
});
