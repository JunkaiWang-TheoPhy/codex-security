import { CodexSecurityError } from "./errors.js";
import { type ExternalImportTarget } from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import {
  hasInspectorEvidence,
  inspectorReportRepositories,
  readInspectorFindings,
} from "./inspector-findings.js";
import {
  blackDuckReportRepositories,
  hasBlackDuckEvidence,
  readBlackDuckFindings,
} from "./blackduck-findings.js";
import {
  hasVeracodeEvidence,
  readVeracodeFindings,
  veracodeReportRepositories,
} from "./veracode-findings.js";

interface BoundScanner {
  label: string;
  read: typeof readInspectorFindings;
  hasEvidence(data: unknown, id: string): boolean;
  repositories: typeof inspectorReportRepositories;
}

export const repositoryBoundScanners: Partial<Record<Provider, BoundScanner>> =
  {
    inspector: {
      label: "Inspector",
      read: readInspectorFindings,
      hasEvidence: hasInspectorEvidence,
      repositories: inspectorReportRepositories,
    },
    blackduck: {
      label: "Black Duck",
      read: readBlackDuckFindings,
      hasEvidence: hasBlackDuckEvidence,
      repositories: blackDuckReportRepositories,
    },
    veracode: {
      label: "Veracode",
      read: readVeracodeFindings,
      hasEvidence: hasVeracodeEvidence,
      repositories: veracodeReportRepositories,
    },
  };

export function boundScannerRepositories(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
): Map<string, ExternalSourceRepository> {
  for (const [name, scanner] of Object.entries(repositoryBoundScanners)) {
    if (
      name !== provider &&
      findings.some(({ evidence, source_finding_id }) =>
        scanner.hasEvidence(evidence.source_data, source_finding_id),
      )
    )
      throw new CodexSecurityError(
        `Retained ${scanner.label} evidence requires the ${name} provider.`,
      );
  }
  return (
    repositoryBoundScanners[provider]?.repositories(findings, target) ??
    new Map()
  );
}
