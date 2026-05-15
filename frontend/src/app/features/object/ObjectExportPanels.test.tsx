import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ObjectExportToolbar } from "./ObjectExportPanels";

describe("ObjectExportToolbar", () => {
  it("filters object kinds through the global select", async () => {
    const onTypeFilterChange = vi.fn();
    render(
      <ObjectExportToolbar
        count={3}
        query=""
        typeFilter="all"
        onQueryChange={vi.fn()}
        onTypeFilterChange={onTypeFilterChange}
      />,
    );

    fireEvent.pointerDown(screen.getByRole("combobox", { name: "对象类型" }), {
      button: 0,
      ctrlKey: false,
      pointerType: "mouse",
    });
    const imageOption = await screen.findByRole("option", { name: "图片" });
    fireEvent.keyDown(imageOption, { key: "Enter" });

    expect(onTypeFilterChange).toHaveBeenCalledWith("image");
  });
});
