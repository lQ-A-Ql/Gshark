// Feature: iterative-dev-governance, Property 13: Contract mapper round-trip preserves data
// Validates: Requirements 5.6
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { DecryptionConfig } from "../../core/types";
import { asPluginSource, toPluginSourceRequest, type PluginSource } from "./pluginSourceMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./tlsMapper";

describe("Property 13: contract mapper round-trip preserves data", () => {
  it("plugin source: decode(encode(x)) deep-equals x for any well-formed PluginSource", () => {
    fc.assert(
      fc.property(
        fc.record<PluginSource>({
          id: fc.string(),
          configPath: fc.string(),
          configContent: fc.string(),
          logicPath: fc.string(),
          logicContent: fc.string(),
          entry: fc.string(),
        }),
        (source) => {
          const encoded = toPluginSourceRequest(source);
          const decoded = asPluginSource(encoded, source.id);
          expect(decoded).toEqual(source);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("decryption config: decode(encode(x)) deep-equals x for any well-formed DecryptionConfig", () => {
    fc.assert(
      fc.property(
        fc.record<DecryptionConfig>({
          sslKeyLogPath: fc.string(),
          privateKeyPath: fc.string(),
          privateKeyIpPort: fc.string(),
        }),
        (config) => {
          const encoded = toDecryptionConfigRequest(config);
          const decoded = asDecryptionConfig(encoded);
          expect(decoded).toEqual(config);
        },
      ),
      { numRuns: 100 },
    );
  });
});
