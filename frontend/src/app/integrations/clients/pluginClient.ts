import type { DBCProfile, DecryptionConfig, PluginItem } from "../../core/types";
import { asDBCProfiles, asPluginItem, asPluginItems } from "../mappers/pluginMapper";
import { asPluginSource, toPluginSourceRequest, type PluginSource } from "../mappers/pluginSourceMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "../mappers/tlsMapper";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface PluginClient {
  listVehicleDBCProfiles(): Promise<DBCProfile[]>;
  addVehicleDBC(path: string): Promise<DBCProfile[]>;
  removeVehicleDBC(path: string): Promise<DBCProfile[]>;
  listPlugins(): Promise<PluginItem[]>;
  getPluginSource(id: string): Promise<PluginSource>;
  savePluginSource(source: PluginSource): Promise<PluginSource>;
  addPlugin(plugin: PluginItem): Promise<PluginItem>;
  deletePlugin(id: string): Promise<void>;
  togglePlugin(id: string): Promise<PluginItem>;
  setPluginsEnabled(ids: string[], enabled: boolean): Promise<PluginItem[]>;
  getTLSConfig(): Promise<DecryptionConfig | null>;
  updateTLSConfig(cfg: DecryptionConfig): Promise<void>;
}

export function createPluginClient(request: JsonRequest): PluginClient {
  return {
    async listVehicleDBCProfiles() {
      const rows = await request<any[]>("/api/analysis/vehicle/dbc");
      return asDBCProfiles(rows);
    },

    async addVehicleDBC(path: string) {
      const rows = await request<any[]>("/api/analysis/vehicle/dbc", {
        method: "POST",
        body: JSON.stringify({ path }),
      });
      return asDBCProfiles(rows);
    },

    async removeVehicleDBC(path: string) {
      const rows = await request<any[]>(`/api/analysis/vehicle/dbc?path=${encodeURIComponent(path)}`, {
        method: "DELETE",
      });
      return asDBCProfiles(rows);
    },

    async listPlugins() {
      const rows = await request<any[]>("/api/plugins");
      return asPluginItems(rows);
    },

    async getPluginSource(id: string) {
      const payload = await request<any>(`/api/plugins/source?id=${encodeURIComponent(id)}`);
      return asPluginSource(payload, id);
    },

    async savePluginSource(source: PluginSource) {
      const payload = await request<any>(`/api/plugins/source`, {
        method: "POST",
        body: JSON.stringify(toPluginSourceRequest(source)),
      });
      return asPluginSource(payload, source.id);
    },

    async addPlugin(plugin: PluginItem) {
      const item = await request<any>(`/api/plugins/add`, {
        method: "POST",
        body: JSON.stringify({
          id: String(plugin.id),
          name: plugin.name,
          version: plugin.version,
          tag: plugin.tag,
          author: plugin.author,
          enabled: plugin.enabled,
          entry: plugin.entry || "",
          capabilities: Array.isArray(plugin.capabilities) ? plugin.capabilities : [],
        }),
      });
      return asPluginItem(item);
    },

    async deletePlugin(id: string) {
      await request(`/api/plugins/delete?id=${encodeURIComponent(id)}`, { method: "POST" });
    },

    async togglePlugin(id: string) {
      const item = await request<any>(`/api/plugins/toggle?id=${encodeURIComponent(id)}`, { method: "POST" });
      return asPluginItem(item);
    },

    async setPluginsEnabled(ids: string[], enabled: boolean) {
      const rows = await request<any[]>(`/api/plugins/bulk`, {
        method: "POST",
        body: JSON.stringify({ ids, enabled }),
      });
      return asPluginItems(rows);
    },

    async getTLSConfig() {
      try {
        const cfg = await request<any>("/api/tls");
        return asDecryptionConfig(cfg);
      } catch {
        return null;
      }
    },

    async updateTLSConfig(cfg: DecryptionConfig) {
      await request("/api/tls", {
        method: "POST",
        body: JSON.stringify(toDecryptionConfigRequest(cfg)),
      });
    },
  };
}
