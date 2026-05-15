import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GenericMiscSelectField } from "./GenericMiscSelectField";

describe("GenericMiscSelectField", () => {
  it("keeps placeholder and selected value behavior with the global select", async () => {
    const onChange = vi.fn();
    render(
      <GenericMiscSelectField
        disabled={false}
        value=""
        onChange={onChange}
        field={{
          name: "mode",
          label: "Mode",
          type: "select",
          placeholder: "请选择模式",
          options: [
            { value: "fast", label: "快速" },
            { value: "deep", label: "深度" },
          ],
        }}
      />,
    );

    expect(screen.getByRole("combobox", { name: "Mode" })).toHaveTextContent("请选择模式");
    fireEvent.pointerDown(screen.getByRole("combobox", { name: "Mode" }), {
      button: 0,
      ctrlKey: false,
      pointerType: "mouse",
    });
    const deepOption = await screen.findByRole("option", { name: "深度" });
    fireEvent.keyDown(deepOption, { key: "Enter" });

    expect(onChange).toHaveBeenCalledWith("deep");
  });
});
