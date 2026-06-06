import { describe, expect, it } from "vitest";
import { deriveIndustrialDnp3Section, mergeBuckets } from "./industrialDnp3SectionModel";

describe("industrial DNP3 section model", () => {
  it("derives rows from details, commands, and rules", () => {
    const section = deriveIndustrialDnp3Section(
      [
        {
          name: "DNP3",
          totalFrames: 1,
          operations: [{ label: "select", count: 1 }],
          targets: [],
          results: [],
          records: [{ packetId: 1, time: "t1", source: "a", destination: "b", operation: "select", summary: "detail" }],
        },
      ],
      [
        {
          packetId: 2,
          time: "t2",
          protocol: "DNP3",
          source: "a",
          destination: "c",
          operation: "operate",
          target: "outstation",
          value: "1",
          result: "ok",
          summary: "command",
        },
      ],
      [{ rule: "dnp3-burst", level: "high", packetId: 3, functionName: "operate", summary: "rule" }],
    );

    expect(section?.rowCount).toBe(3);
    expect(section?.commandCount).toBe(1);
    expect(section?.ruleCount).toBe(1);
    expect(section?.rows.map((row) => row.sourceType)).toEqual(["detail", "command", "rule"]);
  });

  it("merges and sorts buckets by count then label", () => {
    expect(mergeBuckets([{ label: "b", count: 1 }], ["a", "b"])).toEqual([
      { label: "b", count: 2 },
      { label: "a", count: 1 },
    ]);
  });
});
