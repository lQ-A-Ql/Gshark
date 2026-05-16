import { backendClients } from "../../integrations/backendClients";

export async function getBackendUnavailableStatus() {
  const desktopStatus = await backendClients.runtime.getDesktopBackendStatus().catch(() => "");
  const detail = desktopStatus.trim();
  return detail && detail !== "not-started" && detail !== "starting" ? detail : "桌面后端未连接，请启动或重启桌面应用";
}
