// Feature: iterative-dev-governance, Property 13: Contract mapper round-trip preserves data
// Validates: Requirements 5.6
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { DecryptionConfig } from "../../core/types";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./tlsMapper";

describe("Property 13: contract mapper round-trip preserves data", () => {
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
