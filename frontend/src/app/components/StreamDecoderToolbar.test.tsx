import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { StreamDecoderToolbar } from "./StreamDecoderToolbar";

describe("StreamDecoderToolbar", () => {
  it("runs decoders and opens decoder settings", () => {
    const onRunDecoder = vi.fn();
    const onOpenSettings = vi.fn();
    render(
      <StreamDecoderToolbar
        runningDecoder={null}
        disabled={false}
        onRunDecoder={onRunDecoder}
        onOpenSettings={onOpenSettings}
        onCancel={vi.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Base64/ }));
    fireEvent.click(screen.getAllByTitle("解码设置")[0]);

    expect(onRunDecoder).toHaveBeenCalledWith("base64");
    expect(onOpenSettings).toHaveBeenCalledWith("behinder");
  });

  it("shows cancel action while a decoder is running", () => {
    const onCancel = vi.fn();
    render(
      <StreamDecoderToolbar
        runningDecoder="godzilla"
        disabled={false}
        onRunDecoder={vi.fn()}
        onOpenSettings={vi.fn()}
        onCancel={onCancel}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "取消" }));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
