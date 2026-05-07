import { describe, expect, it } from "vitest";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./tlsMapper";

describe("tlsMapper", () => {
  it("maps decryption config both ways", () => {
    const cfg = asDecryptionConfig({
      ssl_key_log_file: "a",
      rsa_private_key: "b",
      target_ip_port: "c",
    });

    expect(cfg).toMatchObject({ sslKeyLogPath: "a", privateKeyPath: "b", privateKeyIpPort: "c" });
    expect(toDecryptionConfigRequest(cfg)).toMatchObject({
      ssl_key_log_file: "a",
      rsa_private_key: "b",
      target_ip_port: "c",
    });
  });
});
