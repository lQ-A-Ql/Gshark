import { describe, expect, it } from "vitest";
import { asPluginSource, toPluginSourceRequest } from "./pluginSourceMapper";

describe("pluginSourceMapper", () => {
  it("maps plugin source payload and request shape", () => {
    const source = asPluginSource(
      {
        id: "x",
        config_path: "cfg",
        config_content: "content",
        logic_path: "logic",
        logic_content: "code",
        entry: "main",
      },
      "fallback",
    );

    expect(source).toMatchObject({
      id: "x",
      configPath: "cfg",
      logicContent: "code",
    });
    expect(toPluginSourceRequest(source)).toMatchObject({
      id: "x",
      config_path: "cfg",
      logic_content: "code",
    });
  });
});
