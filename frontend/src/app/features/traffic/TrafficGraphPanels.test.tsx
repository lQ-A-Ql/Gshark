import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TrafficGraphPanels } from "./TrafficGraphPanels";

const baseProps = {
  protocolDist: [],
  timeline: [],
  topComputerNames: [],
  topDestPorts: [],
  topDomains: [],
  topDstIPs: [],
  topSrcIPs: [],
  topSrcPorts: [],
  topTalkers: [],
  topConversations: [],
  protocolHierarchy: [],
  evidenceRecords: [],
  evidenceLoading: false,
  evidenceError: null,
  selectedSection: "overview" as const,
  timelineSelection: { hoveredLabel: null, lockedLabel: null, selectedRange: null },
  onSelectSection: () => {},
  onTimelineHoverLabel: () => {},
  onTimelineLockedLabel: () => {},
  onTimelineRangeSelect: () => {},
  onTimelineClearSelection: () => {},
  onJumpFilter: () => {},
};

describe("TrafficGraphPanels", () => {
  it("switches sections from the sidebar and renders only the selected panel", () => {
    const onSelectSection = vi.fn();

    render(<TrafficGraphPanels {...baseProps} selectedSection="trend" onSelectSection={onSelectSection} />);

    expect(screen.getAllByText("流量时间线").length).toBeGreaterThan(0);
    expect(screen.queryByText("会话拓扑 (源 → 目标)")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /协议分布/i }));
    expect(onSelectSection).toHaveBeenCalledWith("protocols");
  });

  it("renders explicit conversation topology edges", () => {
    const { container } = render(
      <TrafficGraphPanels
        {...baseProps}
        selectedSection="topology"
        topConversations={[{ src: "10.0.0.1", dst: "10.0.0.2", count: 4 }]}
      />,
    );

    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2")).toBeInTheDocument();
    expect(container.querySelectorAll("path[marker-end='url(#topo-arrow)']")).toHaveLength(1);
  });

  it("does not fabricate topology edges from endpoint-only top talkers", () => {
    const { container } = render(
      <TrafficGraphPanels
        {...baseProps}
        selectedSection="topology"
        topTalkers={[{ label: "10.0.0.1", count: 1 }]}
        topConversations={[]}
      />,
    );

    expect(screen.getByText("暂无会话拓扑数据")).toBeInTheDocument();
    expect(container.querySelectorAll("path[marker-end='url(#topo-arrow)']")).toHaveLength(0);
  });

  it("renders timeline markers and forwards marker selection", () => {
    const onTimelineLockedLabel = vi.fn();

    render(
      <TrafficGraphPanels
        {...baseProps}
        selectedSection="trend"
        timeline={[
          { label: "12:00:00", count: 2 },
          { label: "12:00:01", count: 15 },
          { label: "12:00:02", count: 4 },
        ]}
        onTimelineLockedLabel={onTimelineLockedLabel}
      />,
    );

    const marker = screen.getByTestId("timeline-event-marker-peak-12:00:01");
    fireEvent.click(marker);
    expect(onTimelineLockedLabel).toHaveBeenCalledWith("12:00:01");
    expect(screen.getByRole("button", { name: "清除选择" })).toBeInTheDocument();
  });

  it("shows scoped global warning when timeline selection exists in non-trend sections", () => {
    render(
      <TrafficGraphPanels
        {...baseProps}
        selectedSection="protocols"
        timelineSelection={{
          hoveredLabel: null,
          lockedLabel: "12:00:01",
          selectedRange: { startLabel: "12:00:00", endLabel: "12:00:02" },
        }}
      />,
    );

    expect(screen.getAllByText("已选择时间窗口/时间点；当前卡片仍展示全局统计，窗口统计待接入。").length).toBeGreaterThan(0);
  });

  it("passes timeline selection context into the topology reference highlight", () => {
    render(
      <TrafficGraphPanels
        {...baseProps}
        selectedSection="topology"
        timelineSelection={{
          hoveredLabel: null,
          lockedLabel: null,
          selectedRange: { startLabel: "12:00:00", endLabel: "12:00:02" },
        }}
        topConversations={[{ src: "10.0.0.1", dst: "10.0.0.2", count: 4 }]}
      />,
    );

    expect(screen.getByTestId("traffic-topology-linked-context")).toHaveTextContent("12:00:00 ~ 12:00:02");
    expect(screen.getByTestId("traffic-topology-linked-edge")).toBeInTheDocument();
  });

  it("renders Evidence and community YARA markers in the timeline section", () => {
    render(
      <TrafficGraphPanels
        {...baseProps}
        selectedSection="trend"
        timeline={[{ label: "12:00:01", count: 15 }]}
        evidenceRecords={[
          {
            id: "ev-community",
            module: "hunting",
            sourceType: "YARA",
            summary: "社区规则命中",
            confidenceLabel: "unknown",
            severity: "high",
            tags: ["yara"],
            caveats: [],
            metadata: {
              timestamp: "12:00:01",
              rule_pack: "signature-base",
              rule_source: "Neo23x0/signature-base",
              community_rule: "true",
            },
          },
        ]}
      />,
    );

    expect(screen.getByTestId("timeline-evidence-marker-ev-community")).toBeInTheDocument();
    expect(screen.getByText("COMMUNITY")).toBeInTheDocument();
    expect(screen.getByText("Community YARA")).toBeInTheDocument();
  });
});
