import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";
import { getMiscToolsMocks } from "./MiscTools.testHarness";
import MiscTools from "./MiscTools";

const mocks = getMiscToolsMocks();

describe("MiscTools payload confidence states", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("keeps low-confidence auto detection as an explicit review state", async () => {
    mocks.inspectStreamPayload.mockResolvedValueOnce({
      normalizedPayload: "just-random-text",
      candidates: [
        {
          id: "payload-0",
          label: "当前 payload",
          kind: "payload",
          value: "just-random-text",
          confidence: 15,
          decoderHints: ["auto"],
          fingerprints: [],
        },
      ],
      suggestedCandidateId: "payload-0",
      suggestedDecoder: "auto",
      suggestedFamily: "plain",
      confidence: 15,
      reasons: ["已提取出可操作 payload 候选。"],
    });
    mocks.decodeStreamPayload.mockRejectedValueOnce(
      new Error("自动检测置信度不足，请手动选择解码器；失败阶段：Base64: 结果不可读或为空"),
    );

    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    fireEvent.change(await screen.findByPlaceholderText(/POST \/shell\.php/), {
      target: { value: "just-random-text" },
    });
    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));

    expect(await screen.findByText("当前 payload")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "自动检测" }));

    expect(
      await screen.findByText("自动检测置信度不足，请手动选择解码器；失败阶段：Base64: 结果不可读或为空"),
    ).toBeInTheDocument();
  }, 15000);
});
