import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TrafficTopologyGraph } from "./TrafficTopologyGraph";

describe("TrafficTopologyGraph", () => {
  const edges = [{ src: "10.0.0.1", dst: "10.0.0.2", count: 4 }];

  it("zooms the transformed graph content on mouse wheel while preserving arrow markers", () => {
    const { container } = render(<TrafficTopologyGraph edges={edges} height={320} />);

    const viewport = screen.getByTestId("traffic-topology-viewport");
    Object.defineProperty(viewport, "getBoundingClientRect", {
      value: () => ({ left: 0, top: 0, width: 400, height: 320, right: 400, bottom: 320, x: 0, y: 0, toJSON: () => {} }),
    });

    fireEvent.wheel(viewport, { deltaY: -120, clientX: 200, clientY: 160 });

    expect(screen.getByTestId("traffic-topology-content").getAttribute("transform")).toMatch(
      /^translate\(-6(?:\.0+\d*)? -19\.200000000000017\) scale\(1\.12\)$/,
    );
    expect(container.querySelectorAll("path[marker-end='url(#topo-arrow)']")).toHaveLength(1);
  });

  it("pans the transformed graph content on left-button drag", () => {
    render(<TrafficTopologyGraph edges={edges} height={320} />);

    const viewport = screen.getByTestId("traffic-topology-viewport");
    Object.defineProperty(viewport, "getBoundingClientRect", {
      value: () => ({ left: 0, top: 0, width: 400, height: 320, right: 400, bottom: 320, x: 0, y: 0, toJSON: () => {} }),
    });

    fireEvent.mouseDown(viewport, { button: 0, clientX: 100, clientY: 100 });
    fireEvent.mouseMove(viewport, { clientX: 180, clientY: 148 });
    fireEvent.mouseUp(viewport, { button: 0 });

    expect(screen.getByTestId("traffic-topology-content").getAttribute("transform")).toBe("translate(20 48) scale(1)");
  });

  it("shows linked timeline context and highlights the global reference edge", () => {
    render(<TrafficTopologyGraph edges={edges} height={320} linkedContextLabel="12:00:00 ~ 12:00:02" />);

    expect(screen.getByTestId("traffic-topology-linked-context")).toHaveTextContent("12:00:00 ~ 12:00:02");
    expect(screen.getByTestId("traffic-topology-linked-edge")).toBeInTheDocument();
    expect(screen.getAllByTestId("traffic-topology-linked-node")).toHaveLength(2);
  });
});
