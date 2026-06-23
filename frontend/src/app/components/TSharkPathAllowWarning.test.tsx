import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TSharkPathAllowWarning } from "./TSharkPathAllowWarning";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";

describe("TSharkPathAllowWarning", () => {
  it("renders warning and the directory to allow", () => {
    render(
      <TSharkPathAllowWarning
        status={{
          available: true,
          path: "C:\\Tools\\tshark.exe",
          message: "ok",
          usingCustomPath: true,
          pathWarning: "binary is outside the default trusted directories",
        }}
      />,
    );

    expect(screen.getByText(/binary is outside the default trusted directories/)).toBeInTheDocument();
    expect(screen.getByText(/目录：C:\\Tools/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "加入白名单" })).toBeInTheDocument();
  });

  it("calls allowTSharkDir with the binary parent directory when clicked", async () => {
    const allow = vi.fn().mockResolvedValue({ available: true, path: "C:\\Tools\\tshark.exe", message: "ok", usingCustomPath: true } as TSharkStatus);
    render(
      <TSharkPathAllowWarning
        status={{
          available: true,
          path: "C:\\Tools\\tshark.exe",
          message: "ok",
          usingCustomPath: true,
          pathWarning: "binary is outside the default trusted directories",
        }}
        allowTSharkDir={allow}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "加入白名单" }));
    expect(allow).toHaveBeenCalledWith("C:\\Tools");
  });

  it("stays hidden when there is no path warning", () => {
    const { container } = render(
      <TSharkPathAllowWarning
        status={{
          available: true,
          path: "tshark.exe",
          message: "ok",
          usingCustomPath: false,
        }}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("handles Windows root-level paths", () => {
    const allow = vi.fn().mockResolvedValue({ available: true, path: "C:\\tshark.exe", message: "ok", usingCustomPath: true } as TSharkStatus);
    render(
      <TSharkPathAllowWarning
        status={{
          available: true,
          path: "C:\\tshark.exe",
          message: "ok",
          usingCustomPath: true,
          pathWarning: "binary is outside the default trusted directories",
        }}
        allowTSharkDir={allow}
      />,
    );

    expect(screen.getByText(/目录：C:\\/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "加入白名单" }));
    expect(allow).toHaveBeenCalledWith("C:\\");
  });
});
