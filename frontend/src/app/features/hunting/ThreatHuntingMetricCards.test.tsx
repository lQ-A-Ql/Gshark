import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ThreatHit } from "../../core/types";
import { ThreatHuntingMetricCards } from "./ThreatHuntingMetricCards";

const hit = (id: number, level: ThreatHit["level"], category: ThreatHit["category"]): ThreatHit => ({
  id,
  category,
  level,
  packetId: id,
  rule: `rule-${id}`,
  preview: `hit-${id}`,
  match: `match-${id}`,
});

describe("ThreatHuntingMetricCards", () => {
  it("renders total, high risk, and category counts", () => {
    render(
      <ThreatHuntingMetricCards
        hits={[hit(1, "critical", "CTF"), hit(2, "medium", "Anomaly"), hit(3, "high", "OWASP")]}
        stats={{ ctf: 1, owasp: 1, anomaly: 1 }}
      />,
    );

    expect(screen.getByText("总命中")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("高风险")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("CTF / 异常")).toBeInTheDocument();
    expect(screen.getByText("1 / 1")).toBeInTheDocument();
  });
});
