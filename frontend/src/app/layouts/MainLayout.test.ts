import { describe, expect, it, vi } from "vitest";
import { getRouteMotionDirection, installBrowserPageDragGuard, preventBrowserPageDrag } from "./MainLayout";

describe("MainLayout drag guard", () => {
  it("prevents native browser drag navigation", () => {
    const event = {
      preventDefault: vi.fn(),
      stopPropagation: vi.fn(),
    };

    preventBrowserPageDrag(event);

    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    expect(event.stopPropagation).toHaveBeenCalledTimes(1);
  });

  it("allows explicitly marked drop zones to handle drag events themselves", () => {
    const dropZone = document.createElement("div");
    const child = document.createElement("button");
    dropZone.dataset.gsharkDropZone = "true";
    dropZone.appendChild(child);
    const event = {
      preventDefault: vi.fn(),
      stopPropagation: vi.fn(),
      target: child,
    };

    preventBrowserPageDrag(event);

    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(event.stopPropagation).not.toHaveBeenCalled();
  });

  it("blocks dragstart events installed on the document capture phase", () => {
    const cleanup = installBrowserPageDragGuard();
    const dragEvent = new Event("dragstart", { bubbles: true, cancelable: true });

    document.body.dispatchEvent(dragEvent);
    cleanup();

    expect(dragEvent.defaultPrevented).toBe(true);
  });

  it("removes installed drag guards during cleanup", () => {
    const cleanup = installBrowserPageDragGuard();
    cleanup();
    const dragEvent = new Event("dragstart", { bubbles: true, cancelable: true });

    document.body.dispatchEvent(dragEvent);

    expect(dragEvent.defaultPrevented).toBe(false);
  });
});

describe("MainLayout route motion", () => {
  it("computes stable route motion directions from navigation order", () => {
    expect(getRouteMotionDirection("/", "/c2-analysis")).toBe("forward");
    expect(getRouteMotionDirection("/c2-analysis", "/traffic-graph")).toBe("back");
    expect(getRouteMotionDirection("/c2-analysis", "/c2-analysis")).toBe("neutral");
    expect(getRouteMotionDirection("/unknown", "/c2-analysis")).toBe("neutral");
  });
});
