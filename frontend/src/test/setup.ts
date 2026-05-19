import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

class PointerEventMock extends MouseEvent {
  pointerId: number;
  pointerType: string;

  constructor(type: string, props: PointerEventInit = {}) {
    super(type, props);
    this.pointerId = props.pointerId ?? 1;
    this.pointerType = props.pointerType ?? "mouse";
  }
}

const localStorageMock = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
  clear: () => {},
};

const canvasContextMock: Partial<CanvasRenderingContext2D> = {
  arc: () => {},
  beginPath: () => {},
  clearRect: () => {},
  fill: () => {},
  lineTo: () => {},
  moveTo: () => {},
  restore: () => {},
  save: () => {},
  setTransform: () => {},
  stroke: () => {},
};

afterEach(() => {
  cleanup();
});

configure({
  asyncUtilTimeout: 3000,
});

Object.defineProperty(globalThis, "ResizeObserver", {
  writable: true,
  value: ResizeObserverMock,
});

Object.defineProperty(window, "localStorage", {
  writable: true,
  value: localStorageMock,
});

Object.defineProperty(window, "PointerEvent", {
  writable: true,
  value: PointerEventMock,
});

Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  writable: true,
  value: () => canvasContextMock,
});

if (!HTMLElement.prototype.hasPointerCapture) {
  HTMLElement.prototype.hasPointerCapture = () => false;
}

if (!HTMLElement.prototype.setPointerCapture) {
  HTMLElement.prototype.setPointerCapture = () => {};
}

if (!HTMLElement.prototype.releasePointerCapture) {
  HTMLElement.prototype.releasePointerCapture = () => {};
}

if (!HTMLElement.prototype.scrollIntoView) {
  HTMLElement.prototype.scrollIntoView = () => {};
}
