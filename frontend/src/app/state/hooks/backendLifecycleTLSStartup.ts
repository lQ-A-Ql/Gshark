import type { Dispatch, SetStateAction } from "react";
import type { DecryptionConfig } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { isOperationTimeoutError, withTimeout } from "../../utils/asyncControl";
import { STARTUP_TLS_CONFIG_TIMEOUT_MS } from "../captureConstants";

export async function loadStartupTLSConfig(
  setDecryptionConfig: Dispatch<SetStateAction<DecryptionConfig>>,
  setBackendStatus: Dispatch<SetStateAction<string>>,
) {
  try {
    const tls = await withTimeout(
      backendClients.securityMaterial.getTLSConfig(),
      STARTUP_TLS_CONFIG_TIMEOUT_MS,
      "startup TLS config check timed out",
    );
    if (tls) setDecryptionConfig(tls);
  } catch (error) {
    if (!isOperationTimeoutError(error)) {
      setBackendStatus("后端初始化失败");
    }
  }
}
