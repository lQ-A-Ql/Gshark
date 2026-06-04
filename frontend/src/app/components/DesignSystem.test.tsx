import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MetricCard, StatusHint, SurfacePanel } from "./DesignSystem";

describe("MetricCard", () => {
  it("renders label and value", () => {
    render(<MetricCard label="Packets" value={1234} />);
    expect(screen.getByText("Packets")).toBeInTheDocument();
    expect(screen.getByText("1234")).toBeInTheDocument();
  });

  it("has role=region and aria-label matching the label", () => {
    render(<MetricCard label="Flows" value={42} />);
    const region = screen.getByRole("region", { name: "Flows" });
    expect(region).toBeInTheDocument();
    expect(region).toHaveAttribute("aria-label", "Flows");
  });

  it("renders icon when provided", () => {
    render(<MetricCard label="Bytes" value="1 MB" icon={<span data-testid="icon">📊</span>} />);
    expect(screen.getByTestId("icon")).toBeInTheDocument();
  });
});

describe("StatusHint", () => {
  it("renders children content", () => {
    render(<StatusHint>Connection stable</StatusHint>);
    expect(screen.getByText("Connection stable")).toBeInTheDocument();
  });

  it("applies tone class for emerald tone", () => {
    const { container } = render(<StatusHint tone="emerald">Good</StatusHint>);
    const hint = container.firstElementChild as HTMLElement;
    expect(hint.className).toContain("text-emerald-700");
  });
});

describe("SurfacePanel", () => {
  it("renders children content", () => {
    render(<SurfacePanel>Panel body</SurfacePanel>);
    expect(screen.getByText("Panel body")).toBeInTheDocument();
  });
});
