import { describe, expect, it } from "vitest";
import { clampFloatingPoint, getPointerFloatingPosition } from "./viewportPosition";

describe("viewportPosition", () => {
  const menu = { width: 192, height: 118 };
  const viewport = { width: 800, height: 600 };

  it("keeps a floating point unchanged when it already fits", () => {
    expect(getPointerFloatingPosition(120, 160, menu, { viewport })).toEqual({ x: 120, y: 160 });
  });

  it("clamps right and bottom overflow inside the viewport", () => {
    expect(getPointerFloatingPosition(790, 590, menu, { viewport })).toEqual({ x: 596, y: 470 });
  });

  it("clamps negative coordinates to the safe margin", () => {
    expect(getPointerFloatingPosition(-20, -10, menu, { viewport })).toEqual({ x: 12, y: 12 });
  });

  it("keeps coordinates usable in very small viewports", () => {
    expect(getPointerFloatingPosition(120, 160, menu, { viewport: { width: 160, height: 100 } })).toEqual({
      x: 12,
      y: 12,
    });
  });

  it("supports custom margins and floating sizes", () => {
    expect(
      clampFloatingPoint(
        { x: 490, y: 390 },
        { width: 80, height: 60 },
        { width: 500, height: 400 },
        20,
      ),
    ).toEqual({ x: 400, y: 320 });
  });
});
