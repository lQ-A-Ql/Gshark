import { describe, expect, it, vi } from "vitest";
import { installBrowserPageDragGuard, preventBrowserPageDrag } from "./MainLayout";

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
