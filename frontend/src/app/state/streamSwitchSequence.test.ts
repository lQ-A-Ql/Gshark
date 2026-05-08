import { describe, expect, it } from "vitest";
import {
  bumpAllStreamSwitchSequences,
  bumpStreamSwitchSequence,
  createStreamSwitchSequences,
  isLatestStreamSwitchSequence,
  resetStreamSwitchSequences,
} from "./streamSwitchSequence";

describe("streamSwitchSequence", () => {
  it("tracks per-protocol request sequences", () => {
    const sequences = createStreamSwitchSequences();
    expect(bumpStreamSwitchSequence(sequences, "HTTP")).toBe(1);
    expect(bumpStreamSwitchSequence(sequences, "HTTP")).toBe(2);
    expect(bumpStreamSwitchSequence(sequences, "TCP")).toBe(1);
    expect(sequences).toEqual({
      HTTP: 2,
      TCP: 1,
      UDP: 0,
    });
  });

  it("invalidates prior requests when all protocol sequences are bumped", () => {
    const sequences = createStreamSwitchSequences();
    const requestSeq = bumpStreamSwitchSequence(sequences, "UDP");

    expect(isLatestStreamSwitchSequence(sequences, "UDP", requestSeq, () => true)).toBe(true);

    bumpAllStreamSwitchSequences(sequences);

    expect(isLatestStreamSwitchSequence(sequences, "UDP", requestSeq, () => true)).toBe(false);
  });

  it("respects task current flag and reset behavior", () => {
    const sequences = createStreamSwitchSequences();
    const requestSeq = bumpStreamSwitchSequence(sequences, "TCP");

    expect(isLatestStreamSwitchSequence(sequences, "TCP", requestSeq, () => false)).toBe(false);

    resetStreamSwitchSequences(sequences);

    expect(sequences).toEqual({
      HTTP: 0,
      TCP: 0,
      UDP: 0,
    });
  });
});
