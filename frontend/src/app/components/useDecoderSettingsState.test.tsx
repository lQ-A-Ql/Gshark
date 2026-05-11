import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import type { DecoderHintSource } from "./StreamDecoderWorkbenchUtils";
import { useDecoderSettingsState } from "./useDecoderSettingsState";

describe("useDecoderSettingsState", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("merges source hints into persisted decoder settings", async () => {
    const sourceHint: DecoderHintSource = {
      familyHint: "godzilla_like",
      decoderOptionsHint: { pass: "secret", cipher: "xor" },
    };
    const { result } = renderHook(() => useDecoderSettingsState(sourceHint));

    await waitFor(() => {
      expect(result.current.settings.godzilla.pass).toBe("secret");
      expect(result.current.settings.godzilla.cipher).toBe("xor");
    });
  });
});
