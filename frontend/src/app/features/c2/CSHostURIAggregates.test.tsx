import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { C2HTTPEndpointAggregate } from "../../core/types";
import { CSHostURIAggregates } from "./CSHostURIAggregates";

vi.mock("../../state/SentinelContext", () => ({
  useSentinel: () => ({
    locatePacketById: vi.fn(),
    preparePacketStream: vi.fn(),
  }),
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => vi.fn(),
  };
});

const aggregate: C2HTTPEndpointAggregate = {
  host: "team.example",
  uri: "/submit.php",
  channel: "https",
  total: 8,
  getCount: 3,
  postCount: 5,
  methods: [
    { label: "GET", count: 3 },
    { label: "POST", count: 5 },
  ],
  firstTime: "2026-05-09 10:00:00",
  lastTime: "2026-05-09 10:01:00",
  avgInterval: "10s",
  jitter: "2s",
  intervals: [10, 11, 9],
  streams: [7, 8],
  packets: [101, 108],
  representativePacket: 101,
  confidence: 0.92,
  signalTags: ["beacon-like"],
  scoreFactors: [{ name: "periodic-post", weight: 20, direction: "positive", summary: "POST beacon cadence" }],
  summary: "CS beacon Host / URI 聚合",
};

describe("CSHostURIAggregates", () => {
  it("renders the empty aggregate state", () => {
    render(<CSHostURIAggregates items={[]} />);

    expect(screen.getByText(/尚未形成 CS Host \/ URI 聚合/)).toBeInTheDocument();
  });

  it("renders host URI evidence and action controls", () => {
    render(<CSHostURIAggregates items={[aggregate]} />);

    expect(screen.getByText("team.example")).toBeInTheDocument();
    expect(screen.getByText("/submit.php")).toBeInTheDocument();
    expect(screen.getByText("Total 8")).toBeInTheDocument();
    expect(screen.getByText("CS beacon Host / URI 聚合")).toBeInTheDocument();
    expect(screen.getByText("periodic-post")).toBeInTheDocument();
    expect(screen.getByText("beacon-like")).toBeInTheDocument();
    expect(screen.getByText("定位到包")).toBeInTheDocument();
    expect(screen.getByText("过滤器")).toBeInTheDocument();
  });
});
