import { useMemo } from "react";
import { frontendOnlyModules } from "../misc/frontendModules";
import { MiscToolsShell } from "../misc/MiscToolsShell";
import { useMiscToolsCatalog } from "../misc/useMiscToolsCatalog";

export default function MiscTools() {
  const catalog = useMiscToolsCatalog();
  const allModules = useMemo(
    () => [...catalog.modules, ...frontendOnlyModules.filter((fm) => !catalog.modules.some((m) => m.id === fm.id))],
    [catalog.modules],
  );

  return (
    <MiscToolsShell
      modules={allModules}
      loading={catalog.loading}
      error={catalog.error}
      importing={catalog.importing}
      selectedModuleId={catalog.selectedModuleId}
      onSelectModule={catalog.selectModule}
      onImportModule={catalog.importModule}
      onImportModuleFromNativeDialog={catalog.importModuleFromNativeDialog}
      onModuleDeleted={catalog.moduleDeleted}
    />
  );
}
