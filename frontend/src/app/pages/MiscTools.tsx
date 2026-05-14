import { MiscToolsShell } from "../misc/MiscToolsShell";
import { useMiscToolsCatalog } from "../misc/useMiscToolsCatalog";

export default function MiscTools() {
  const catalog = useMiscToolsCatalog();

  return (
    <MiscToolsShell
      modules={catalog.modules}
      loading={catalog.loading}
      error={catalog.error}
      importing={catalog.importing}
      activeCategory={catalog.activeCategory}
      expandedModules={catalog.expandedModules}
      mountedModules={catalog.mountedModules}
      onCategoryChange={catalog.setActiveCategory}
      onImportModule={catalog.importModule}
      onModuleDeleted={catalog.moduleDeleted}
      onToggleModule={catalog.toggleModule}
    />
  );
}
