import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";
import { getMiscToolsMocks } from "./MiscTools.testHarness";
import MiscTools from "./MiscTools";

const mocks = getMiscToolsMocks();

describe("MiscTools webshell metadata states", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("surfaces China Chopper metadata with an explicit unavailable version state", async () => {
    mocks.listStreamPayloadSources.mockResolvedValueOnce([
      {
        id: "pkt-91-form-caidao",
        method: "POST",
        host: "web.test",
        uri: "/cmd.aspx",
        packetId: 91,
        streamId: 12,
        sourceType: "form",
        paramName: "caidao",
        payload: "password=Y21kPWlwY29uZmln",
        preview: "@eval($_POST['caidao']);",
        confidence: 94,
        signals: ["china-chopper-eval"],
        decoderHints: ["china_chopper", "base64"],
        familyHint: "caidao",
        sourceRole: "script_or_command",
        decoderOptionsHint: { decoder: "china_chopper" },
      },
    ]);

    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    expect((await screen.findAllByText("菜刀 / China Chopper")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("未提供").length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByRole("button", { name: "China Chopper" })).not.toBeInTheDocument();
  }, 15000);
});
