import type { ReactNode } from "react";

export type AnalysisWorkbenchSection = {
  id: string;
  title: string;
  description?: string;
  group?: string;
  badge?: string | number;
  disabled?: boolean;
};

export interface AnalysisWorkbenchShellProps<TSectionId extends string> {
  sections: readonly AnalysisWorkbenchSection[];
  selectedSection: TSectionId;
  onSectionChange: (section: TSectionId) => void;
  title?: string;
  description?: string;
  activeSectionIds?: readonly string[];
  children: ReactNode;
  className?: string;
  contentClassName?: string;
  navLabel?: string;
}
