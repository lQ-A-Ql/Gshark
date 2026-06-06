import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";
import { getMiscToolsMocks } from "./MiscTools.testHarness";
import MiscTools from "./MiscTools";

const mocks = getMiscToolsMocks();

describe("MiscTools payload workbench shell", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("renders the payload decoder module after expansion", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByRole("button", { name: "识别候选" })).toBeInTheDocument();
    });
    expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
  }, 15000);
});
