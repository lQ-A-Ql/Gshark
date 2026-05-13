import type { DecryptionConfig } from "../../core/types";
import { asPlainObject } from "./mapperPrimitives";

export function asDecryptionConfig(input: unknown): DecryptionConfig {
  const payload = asPlainObject(input) ?? {};
  return {
    sslKeyLogPath: String(payload.ssl_key_log_file ?? ""),
    privateKeyPath: String(payload.rsa_private_key ?? ""),
    privateKeyIpPort: String(payload.target_ip_port ?? ""),
  };
}

export function toDecryptionConfigRequest(cfg: DecryptionConfig) {
  return {
    ssl_key_log_file: cfg.sslKeyLogPath,
    rsa_private_key: cfg.privateKeyPath,
    target_ip_port: cfg.privateKeyIpPort,
  };
}
