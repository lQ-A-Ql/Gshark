import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { getRouteMotionDirection, installBrowserPageDragGuard, preventBrowserPageDrag } from "./MainLayout";

const mainLayoutSource = readFileSync(resolve(__dirname, "MainLayout.tsx"), "utf8");
const themeSource = readFileSync(resolve(__dirname, "../../styles/theme.css"), "utf8");

function cssBlock(selector: string) {
  const start = themeSource.indexOf(selector);
  expect(start).toBeGreaterThanOrEqual(0);
  const openBrace = themeSource.indexOf("{", start);
  let depth = 0;

  for (let index = openBrace; index < themeSource.length; index += 1) {
    const char = themeSource[index];
    if (char === "{") depth += 1;
    if (char === "}") depth -= 1;
    if (depth === 0) {
      return themeSource.slice(start, index + 1);
    }
  }

  throw new Error(`CSS block not closed: ${selector}`);
}

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
    dropZone.dataset.meowTrafficDropZone = "true";
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

  it("keeps route outlet wrapper stable across pathname changes", () => {
    expect(mainLayoutSource).not.toContain("key={`route-${location.pathname}`}");
    expect(mainLayoutSource).not.toContain("key={`route-${");
  });

  it("keeps route transition animation to opacity and transform only", () => {
    const routeTransitionBlock = cssBlock(".meow-route-transition {");
    const routeKeyframes = cssBlock("@keyframes meow-route-in");

    expect(routeTransitionBlock).toContain("animation: meow-route-in");
    expect(routeTransitionBlock).toContain("will-change: opacity, transform");
    expect(routeKeyframes).toContain("opacity:");
    expect(routeKeyframes).toContain("transform:");
    expect(routeTransitionBlock + routeKeyframes).not.toMatch(/\b(?:-webkit-)?backdrop-filter\b|\bfilter\s*:|blur\(/);
  });
});
