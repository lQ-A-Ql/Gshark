import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { TrafficGraphOverview } from "./TrafficGraphOverview";

describe("TrafficGraphOverview", () => {
  const emptyStats = {
    totalPackets: 0,
    protocolKinds: 0,
    timeline: [],
    protocolDist: [],
    topTalkers: [],
    topConversations: [],
    topHostnames: [],
    topDomains: [],
    topSrcIPs: [],
    topDstIPs: [],
    topComputerNames: [],
    topDestPorts: [],
    topSrcPorts: [],
    protocolHierarchy: [],
  };

  it("shows loading hint when loading", () => {
    render(
      <TrafficGraphOverview error="" loading={true} stats={emptyStats} timeline={[]} onRetry={() => {}} />,
    );
    expect(screen.getByText("正在加载全局流量统计...")).toBeInTheDocument();
  });

  it("shows error message with retry button", () => {
    render(
      <TrafficGraphOverview error="连接失败" loading={false} stats={emptyStats} timeline={[]} onRetry={() => {}} />,
    );
    expect(screen.getByText("连接失败")).toBeInTheDocument();
    expect(screen.getByText("重试")).toBeInTheDocument();
  });

  it("shows stat cards with packet count and protocol kinds", () => {
    const stats = { ...emptyStats, totalPackets: 12345, protocolKinds: 8 };
    render(
      <TrafficGraphOverview error="" loading={false} stats={stats} timeline={[]} onRetry={() => {}} />,
    );
    expect(screen.getByText("12,345")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
  });

  it("shows time window from timeline range", () => {
    const timeline = [
      { label: "10:00:00", count: 5 },
      { label: "10:00:01", count: 3 },
      { label: "10:00:02", count: 7 },
    ];
    render(
      <TrafficGraphOverview error="" loading={false} stats={emptyStats} timeline={timeline} onRetry={() => {}} />,
    );
    expect(screen.getByText("10:00:00 ~ 10:00:02")).toBeInTheDocument();
  });
});
