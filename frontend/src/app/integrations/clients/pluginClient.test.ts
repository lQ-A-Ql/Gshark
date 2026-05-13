import { describe, expect, it, vi } from "vitest";

import { createPluginClient } from "./pluginClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

describe("pluginClient", () => {
  it("maps DBC profile lifecycle requests", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/api/analysis/vehicle/dbc" && !init) {
        return [{ path: "car.dbc", name: "car", message_count: 1, signal_count: 2 }];
      }
      if (path === "/api/analysis/vehicle/dbc" && init?.method === "POST") {
        expect(init.body).toBe(JSON.stringify({ path: "truck.dbc" }));
        return [{ path: "truck.dbc", name: "truck", message_count: 3, signal_count: 4 }];
      }
      expect(path).toBe("/api/analysis/vehicle/dbc?path=truck.dbc");
      expect(init?.method).toBe("DELETE");
      return [];
    }) as unknown as JsonRequest;
    const client = createPluginClient(request);

    await expect(client.listVehicleDBCProfiles()).resolves.toEqual([
      { path: "car.dbc", name: "car", messageCount: 1, signalCount: 2 },
    ]);
    await expect(client.addVehicleDBC("truck.dbc")).resolves.toEqual([
      { path: "truck.dbc", name: "truck", messageCount: 3, signalCount: 4 },
    ]);
    await expect(client.removeVehicleDBC("truck.dbc")).resolves.toEqual([]);
  });

  it("maps plugin source and plugin item mutation requests", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/api/plugins") return [{ id: "echo", name: "Echo", enabled: true }];
      if (path === "/api/plugins/source?id=echo") {
        return { id: "echo", config_path: "cfg", logic_path: "logic", entry: "main" };
      }
      if (path === "/api/plugins/source") {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toMatchObject({ id: "echo", config_path: "cfg2" });
        return { id: "echo", config_path: "cfg2", entry: "main" };
      }
      if (path === "/api/plugins/add") {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toMatchObject({ id: "new", capabilities: ["run"] });
        return { id: "new", name: "New", enabled: false, capabilities: ["run"] };
      }
      if (path === "/api/plugins/toggle?id=echo") return { id: "echo", enabled: false };
      if (path === "/api/plugins/bulk") {
        expect(JSON.parse(String(init?.body))).toEqual({ ids: ["echo"], enabled: true });
        return [{ id: "echo", enabled: true }];
      }
      throw new Error(`unexpected path ${path}`);
    }) as unknown as JsonRequest;
    const client = createPluginClient(request);

    await expect(client.listPlugins()).resolves.toMatchObject([{ id: "echo", name: "Echo", enabled: true }]);
    await expect(client.getPluginSource("echo")).resolves.toMatchObject({ id: "echo", configPath: "cfg" });
    await expect(
      client.savePluginSource({
        id: "echo",
        configPath: "cfg2",
        configContent: "",
        logicPath: "logic",
        logicContent: "",
        entry: "main",
      }),
    ).resolves.toMatchObject({ id: "echo", configPath: "cfg2" });
    await expect(
      client.addPlugin({
        id: "new",
        name: "New",
        version: "",
        tag: "",
        author: "",
        enabled: false,
        entry: "",
        runtime: "",
        capabilities: ["run"],
      }),
    ).resolves.toMatchObject({ id: "new", capabilities: ["run"] });
    await expect(client.togglePlugin("echo")).resolves.toMatchObject({ id: "echo", enabled: false });
    await expect(client.setPluginsEnabled(["echo"], true)).resolves.toMatchObject([{ id: "echo", enabled: true }]);
  });

  it("handles delete and TLS config requests", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/api/plugins/delete?id=echo") {
        expect(init?.method).toBe("POST");
        return {};
      }
      if (path === "/api/tls" && !init) {
        return { ssl_key_log_file: "ssl.log", rsa_private_key: "key.pem", target_ip_port: "10.0.0.1:443" };
      }
      if (path === "/api/tls" && init?.method === "POST") {
        expect(JSON.parse(String(init.body))).toEqual({
          ssl_key_log_file: "ssl.log",
          rsa_private_key: "key.pem",
          target_ip_port: "10.0.0.1:443",
        });
        return {};
      }
      throw new Error(`unexpected path ${path}`);
    }) as unknown as JsonRequest;
    const client = createPluginClient(request);

    await expect(client.deletePlugin("echo")).resolves.toBeUndefined();
    const cfg = await client.getTLSConfig();
    expect(cfg).toEqual({ sslKeyLogPath: "ssl.log", privateKeyPath: "key.pem", privateKeyIpPort: "10.0.0.1:443" });
    expect(cfg).not.toBeNull();
    if (!cfg) throw new Error("expected TLS config");
    await expect(client.updateTLSConfig(cfg)).resolves.toBeUndefined();
  });
});
