import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";
import { getMiscToolsMocks } from "./MiscTools.testHarness";
import MiscTools from "./MiscTools";

const mocks = getMiscToolsMocks();
const SAMPLE_BASE64_PAYLOAD = "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==";

describe("MiscTools payload source loading", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("loads suspicious URI sources and fills the payload textarea from a selected source", async () => {
    mocks.listStreamPayloadSources.mockResolvedValueOnce([
      {
        id: "pkt-81-form-pass",
        method: "POST",
        host: "web.test",
        uri: "/shell.php",
        packetId: 81,
        streamId: 9,
        sourceType: "form",
        paramName: "pass",
        payload: SAMPLE_BASE64_PAYLOAD,
        preview: SAMPLE_BASE64_PAYLOAD,
        confidence: 92,
        signals: ["suspicious-uri", "suspicious-param", "script-after-base64"],
        decoderHints: ["antsword", "base64"],
        familyHint: "antsword_like",
        sourceRole: "script_or_command",
        decoderOptionsHint: { decoder: "antsword", pass: "pass", extractParam: true, urlDecodeRounds: 1 },
      },
    ]);
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    expect(await screen.findByText("可疑 URI / 参数来源")).toBeInTheDocument();
    const sourceButton = (await screen.findByText(/web\.test\/shell\.php/)).closest("button");
    expect(sourceButton).toBeTruthy();
    fireEvent.click(sourceButton!);

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith(SAMPLE_BASE64_PAYLOAD, expect.any(AbortSignal));
    });
    expect(screen.getByDisplayValue(SAMPLE_BASE64_PAYLOAD)).toBeInTheDocument();
    expect(screen.getByText(/当前输入来自 packet #81/)).toBeInTheDocument();
    expect((await screen.findAllByText("AntSword")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("script_or_command").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("未提供").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole("button", { name: "AntSword" }));
    await waitFor(() => {
      expect(mocks.decodeStreamPayload).toHaveBeenCalledWith(
        "antsword",
        SAMPLE_BASE64_PAYLOAD,
        expect.objectContaining({ pass: "pass", extractParam: true, urlDecodeRounds: 1 }),
        expect.any(AbortSignal),
      );
    });
  }, 30000);

  it("keeps manual payload workflow available when no capture is loaded", async () => {
    mocks.sentinelState.fileMeta.path = "";
    mocks.sentinelState.fileMeta.name = "";
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    expect(await screen.findByText(/可先手动粘贴 payload/)).toBeInTheDocument();
    expect(mocks.listStreamPayloadSources).not.toHaveBeenCalled();
  });
});
