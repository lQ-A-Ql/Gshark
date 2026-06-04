import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { AnalysisHero } from "./AnalysisHero";

const defaultProps = {
  icon: <span data-testid="icon">🔍</span>,
  title: "Test Title",
  subtitle: "Test Subtitle",
  tags: ["tag1", "tag2"],
};

describe("AnalysisHero", () => {
  it("renders title", () => {
    render(<AnalysisHero {...defaultProps} />);
    expect(screen.getByText("Test Title")).toBeInTheDocument();
  });

  it("renders subtitle", () => {
    render(<AnalysisHero {...defaultProps} />);
    expect(screen.getByText("Test Subtitle")).toBeInTheDocument();
  });

  it("renders tags", () => {
    render(<AnalysisHero {...defaultProps} />);
    expect(screen.getByText("tag1")).toBeInTheDocument();
    expect(screen.getByText("tag2")).toBeInTheDocument();
  });

  it("renders description when provided", () => {
    render(<AnalysisHero {...defaultProps} description="A description" />);
    expect(screen.getByText("A description")).toBeInTheDocument();
  });

  it("refresh button has aria-label", () => {
    render(<AnalysisHero {...defaultProps} onRefresh={() => {}} />);
    const btn = screen.getByRole("button", { name: "刷新分析" });
    expect(btn).toBeInTheDocument();
  });

  it("calls onRefresh when refresh button is clicked", () => {
    const onRefresh = vi.fn();
    render(<AnalysisHero {...defaultProps} onRefresh={onRefresh} />);
    const btn = screen.getByRole("button", { name: "刷新分析" });
    fireEvent.click(btn);
    expect(onRefresh).toHaveBeenCalledOnce();
  });

  it("does not render refresh button when onRefresh is not provided", () => {
    render(<AnalysisHero {...defaultProps} />);
    expect(screen.queryByRole("button", { name: "刷新分析" })).not.toBeInTheDocument();
  });
});
