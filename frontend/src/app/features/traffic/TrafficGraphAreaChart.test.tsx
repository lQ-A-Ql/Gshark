import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TrafficAreaChart } from "./TrafficAreaChart";

describe("TrafficAreaChart", () => {
  it("renders a valid one-point chart instead of an empty path", () => {
    const { container } = render(<TrafficAreaChart data={[{ label: "12:00:00", count: 5 }]} color="var(--color-chart-2)" />);

    expect(screen.queryByText("暂无时序数据")).not.toBeInTheDocument();
    expect(container.querySelectorAll("circle")).toHaveLength(1);
    expect(screen.getByTestId("traffic-area-line").getAttribute("d")).toMatch(/^M[\d.]+,[\d.]+ L[\d.]+,[\d.]+$/);
    expect(screen.getByTestId("traffic-area-fill").getAttribute("d")).toContain("Z");
  });

  it("uses a stable responsive viewport without non-uniform preserveAspectRatio stretching", () => {
    render(
      <TrafficAreaChart
        data={[
          { label: "12:00:00", count: 1 },
          { label: "12:00:01", count: 3 },
          { label: "12:00:02", count: 2 },
        ]}
        height={220}
      />,
    );

    const chart = screen.getByTestId("traffic-area-chart");
    expect(chart.getAttribute("preserveAspectRatio")).toBe("xMinYMin meet");
    expect(chart.getAttribute("viewBox")).toBe("0 0 640 220");
  });

  it("drops malformed points and preserves the empty state when nothing valid remains", () => {
    render(
      <TrafficAreaChart
        data={[
          { label: "bad", count: 10 },
          { label: "12:00:00", count: Number.NaN },
          { label: "", count: 5 },
        ]}
      />,
    );

    expect(screen.getByText("暂无时序数据")).toBeInTheDocument();
  });

  it("supports hover, locked point, and brush range selection", () => {
    const onHoverPoint = vi.fn();
    const onSelectPoint = vi.fn();
    const onSelectRange = vi.fn();

    const widthSpy = vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(() => ({
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      right: 640,
      bottom: 220,
      width: 640,
      height: 220,
      toJSON: () => ({}),
    }));

    render(
      <TrafficAreaChart
        data={[
          { label: "12:00:00", count: 1 },
          { label: "12:00:01", count: 5 },
          { label: "12:00:02", count: 3 },
        ]}
        hoveredLabel="12:00:01"
        lockedLabel="12:00:02"
        selectedRange={{ startLabel: "12:00:00", endLabel: "12:00:02" }}
        onHoverPoint={onHoverPoint}
        onSelectPoint={onSelectPoint}
        onSelectRange={onSelectRange}
      />,
    );

    const chart = screen.getByTestId("traffic-area-chart");
    fireEvent.mouseMove(chart, { clientX: 320 });
    expect(onHoverPoint).toHaveBeenCalled();

    const lockedPoint = screen.getByTestId("traffic-area-locked-point");
    fireEvent.click(lockedPoint);
    expect(onSelectPoint).toHaveBeenCalledWith({ label: "12:00:02", count: 3 });

    fireEvent.mouseDown(chart, { clientX: 40 });
    fireEvent.mouseMove(chart, { clientX: 620 });
    fireEvent.mouseUp(chart, { clientX: 620 });
    expect(onSelectRange).toHaveBeenCalled();
    expect(screen.getByTestId("traffic-area-selected-range")).toBeInTheDocument();

    widthSpy.mockRestore();
  });
});
