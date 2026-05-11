import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("../misc/EvidenceActions", () => ({
  EvidenceActions: ({ packetId }: { packetId?: number }) => <div data-testid="evidence-actions">{packetId}</div>,
}));

import { InvestigationReportPanel } from "./InvestigationReportPanel";

describe("InvestigationReportPanel", () => {
  it("renders shared summary/evidence/detail/recommendation sections", () => {
    render(
      <InvestigationReportPanel
        preferredProtocol="HTTP"
        report={{
          summary: [{ title: "候选端点", summary: "2 个端点 / 5 次尝试" }],
          evidence: [{ title: "POST /login 疑似爆破", severity: "high", packetId: 11, tags: ["login", "bruteforce"] }],
          details: [{ title: "POST /login", streamId: 3, summary: "状态码 200 / 302" }],
          recommendations: ["打开关联 HTTP 流确认 token 下发。"],
        }}
      />,
    );

    expect(screen.getByText("结构化调查报告")).toBeInTheDocument();
    expect(screen.getByText("POST /login 疑似爆破")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("打开关联 HTTP 流确认 token 下发。")).toBeInTheDocument();
    expect(screen.getByTestId("evidence-actions")).toHaveTextContent("11");
  });
});
