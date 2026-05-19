import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { releaseMarkdownComponents } from "./UpdateReleaseMarkdown";

describe("releaseMarkdownComponents", () => {
  it("keeps safe absolute and relative links clickable", () => {
    const { rerender } = render(
      <>{releaseMarkdownComponents.a({ href: "https://example.com/a", children: "safe" })}</>,
    );

    expect(screen.getByRole("link", { name: "safe" })).toHaveAttribute("href", "https://example.com/a");

    rerender(<>{releaseMarkdownComponents.a({ href: "/release-notes", children: "relative" })}</>);

    expect(screen.getByRole("link", { name: "relative" })).toHaveAttribute("href", "/release-notes");
  });

  it("blocks dangerous or malformed href values", () => {
    const { rerender } = render(<>{releaseMarkdownComponents.a({ href: "javascript:alert(1)", children: "x" })}</>);

    expect(screen.getByText("x")).not.toHaveAttribute("href");

    rerender(<>{releaseMarkdownComponents.a({ href: " JaVaScRiPt:alert(1)", children: "mixed" })}</>);
    expect(screen.getByText("mixed")).not.toHaveAttribute("href");

    rerender(<>{releaseMarkdownComponents.a({ href: "data:text/html,alert(1)", children: "data" })}</>);
    expect(screen.getByText("data")).not.toHaveAttribute("href");

    rerender(<>{releaseMarkdownComponents.a({ href: "vbscript:msgbox(1)", children: "vb" })}</>);
    expect(screen.getByText("vb")).not.toHaveAttribute("href");

    rerender(<>{releaseMarkdownComponents.a({ href: "https://example.com/\u0001", children: "ctrl" })}</>);
    expect(screen.getByText("ctrl")).not.toHaveAttribute("href");
  });

  it("renders empty href as inert text", () => {
    render(<>{releaseMarkdownComponents.a({ href: "", children: "empty" })}</>);

    expect(screen.getByText("empty")).not.toHaveAttribute("href");
  });
});
