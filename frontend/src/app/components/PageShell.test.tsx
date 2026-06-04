import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { PageShell } from "./PageShell";

describe("PageShell", () => {
  it("renders children content", () => {
    render(
      <PageShell>
        <span>hello</span>
      </PageShell>,
    );
    expect(screen.getByText("hello")).toBeInTheDocument();
  });

  it("has role main on the inner content wrapper", () => {
    render(
      <PageShell>
        <p>content</p>
      </PageShell>,
    );
    const main = screen.getByRole("main");
    expect(main).toBeInTheDocument();
    expect(main).toContainHTML("<p>content</p>");
  });

  it("applies tiled density classes by default", () => {
    const { container } = render(
      <PageShell>
        <span>tile</span>
      </PageShell>,
    );
    const main = container.querySelector('[role="main"]') as HTMLElement;
    expect(main.className).toContain("meow-tile-page");
    expect(main.className).toContain("min-h-full");
  });

  it("applies stacked density classes when layout is stacked", () => {
    const { container } = render(
      <PageShell layout="stacked">
        <span>stacked</span>
      </PageShell>,
    );
    const main = container.querySelector('[role="main"]') as HTMLElement;
    expect(main.className).toContain("max-w-[1380px]");
    expect(main.className).toContain("gap-4");
  });

  it("applies roomy density class overrides for stacked layout", () => {
    const { container } = render(
      <PageShell layout="stacked" density="roomy">
        <span>roomy</span>
      </PageShell>,
    );
    const main = container.querySelector('[role="main"]') as HTMLElement;
    expect(main.className).toContain("max-w-[1400px]");
    expect(main.className).toContain("gap-6");
  });
});
