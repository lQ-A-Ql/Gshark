import { describe, expect, it } from "vitest";
import {
  EVIDENCE_VISIBLE_PAGE_SIZE,
  evidenceFamilyLabel,
  evidenceIocLabel,
  evidencePlaybookLabel,
  evidenceProtocolLabel,
  evidenceRuleLabel,
  evidenceSourceTypeLabel,
  evidenceVersionLabel,
  hasValidPacketId,
  hasValidStreamId,
  moduleLabel,
} from "./evidencePanelRules";
import { record } from "./evidencePanelRules.testFixtures";

describe("evidence record labels", () => {
  it("normalizes labels and unavailable states through shared helpers", () => {
    const chinaChopper = record({ sourceType: "china_chopper", family: "caidao" });
    const webshell = record({ sourceType: "webshell", family: "antsword_like" });
    const dnp3 = record({ sourceType: "dnp3", protocol: "dnp3" });
    const ioc = record({ sourceType: "ioc" });
    const playbook = record({ sourceType: "playbook" });
    const rule = record({ sourceType: "rule" });

    expect(evidenceSourceTypeLabel(chinaChopper.sourceType)).toBe("菜刀 / China Chopper");
    expect(evidenceFamilyLabel(chinaChopper)).toBe("菜刀 / China Chopper");
    expect(evidenceSourceTypeLabel(webshell.sourceType)).toBe("WebShell");
    expect(evidenceVersionLabel(webshell)).toBe("未提供");
    expect(evidenceSourceTypeLabel(record({ sourceType: "ja3" }).sourceType)).toBe("JA3");
    expect(evidenceProtocolLabel(dnp3)).toBe("DNP3");
    expect(evidenceIocLabel(ioc)).toBe("IOC API unavailable");
    expect(evidencePlaybookLabel(playbook)).toBe("Playbook 未提供");
    expect(evidenceRuleLabel(rule)).toBe("Rule 未提供");
  });

  it("keeps module labels, navigation guards, and visible page size stable", () => {
    expect(moduleLabel("media")).toBe("媒体");
    expect(moduleLabel("vehicle")).toBe("车机");
    expect(hasValidPacketId(undefined)).toBe(false);
    expect(hasValidPacketId(12)).toBe(true);
    expect(hasValidStreamId(-1)).toBe(false);
    expect(hasValidStreamId(7)).toBe(true);
    expect(EVIDENCE_VISIBLE_PAGE_SIZE).toBe(200);
  });
});
