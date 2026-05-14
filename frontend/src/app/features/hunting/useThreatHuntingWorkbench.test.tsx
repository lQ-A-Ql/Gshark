import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ThreatHit } from "../../core/types";
import { useThreatHuntingWorkbench } from "./useThreatHuntingWorkbench";

const seedHit: ThreatHit = {
  id: 1,
  packetId: 10,
  category: "CTF",
  rule: "flag-prefix",
  level: "medium",
  preview: "flag{demo}",
  match: "flag{",
};
const seedHits: ThreatHit[] = [seedHit];

function createClient() {
  return {
    listThreatHits: vi.fn().mockResolvedValue([{ ...seedHit, id: 2, packetId: 20, category: "OWASP" }]),
    getHuntingRuntimeConfig: vi.fn().mockResolvedValue({
      prefixes: ["flag{", "ctf{"],
      yaraEnabled: true,
      yaraBin: "yara64.exe",
      yaraRules: "rules",
      yaraTimeoutMs: 30000,
    }),
    updateHuntingRuntimeConfig: vi.fn().mockResolvedValue({
      prefixes: ["flag{"],
      yaraEnabled: false,
      yaraBin: "custom-yara.exe",
      yaraRules: "updated",
      yaraTimeoutMs: 5000,
    }),
  };
}

describe("useThreatHuntingWorkbench", () => {
  it("loads runtime config and builds hit stats from sentinel hits", async () => {
    const client = createClient();
    const { result } = renderHook(() =>
      useThreatHuntingWorkbench({ backendConnected: true, threatHits: seedHits, huntingClient: client }),
    );

    await waitFor(() => expect(result.current.statusText).toBe("已加载狩猎运行参数"));

    expect(client.getHuntingRuntimeConfig).toHaveBeenCalledTimes(1);
    expect(result.current.prefixText).toBe("flag{,ctf{");
    expect(result.current.stats).toEqual({ ctf: 1, owasp: 0, anomaly: 0 });
    expect(result.current.selected?.id).toBe(1);
  });

  it("runs hunting and selects the first returned hit", async () => {
    const client = createClient();
    const { result } = renderHook(() =>
      useThreatHuntingWorkbench({ backendConnected: true, threatHits: seedHits, huntingClient: client }),
    );
    await waitFor(() => expect(client.getHuntingRuntimeConfig).toHaveBeenCalledTimes(1));

    await act(async () => {
      await result.current.runHunt(["owasp"]);
    });

    expect(client.listThreatHits).toHaveBeenCalledWith(["owasp"]);
    expect(result.current.selectedHit).toBe(2);
    expect(result.current.statusText).toBe("狩猎完成: 1 条命中");
  });

  it("saves config before rerunning hunting", async () => {
    const client = createClient();
    const { result } = renderHook(() =>
      useThreatHuntingWorkbench({ backendConnected: true, threatHits: seedHits, huntingClient: client }),
    );
    await waitFor(() => expect(client.getHuntingRuntimeConfig).toHaveBeenCalledTimes(1));

    act(() => {
      result.current.setPrefixText("flag{");
      result.current.setYaraEnabled(false);
      result.current.setYaraBin(" custom-yara.exe ");
      result.current.setYaraRules(" updated ");
      result.current.setYaraTimeoutMs(5000);
    });

    await act(async () => {
      await result.current.applyConfigAndRun();
    });

    expect(client.updateHuntingRuntimeConfig).toHaveBeenCalledWith({
      prefixes: ["flag{"],
      yaraEnabled: false,
      yaraBin: "custom-yara.exe",
      yaraRules: "updated",
      yaraTimeoutMs: 5000,
    });
    expect(client.listThreatHits).toHaveBeenCalledWith(["flag{"]);
  });
});
