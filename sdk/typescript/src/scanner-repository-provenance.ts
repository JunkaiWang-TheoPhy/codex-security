import { CodexSecurityError } from "./errors.js";
import { type ExternalImportTarget } from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import {
  hasInspectorEvidence,
  inspectorReportRepositories,
  normalizeInspectorFindings,
} from "./inspector-findings.js";
import {
  blackDuckReportRepositories,
  hasBlackDuckEvidence,
  normalizeBlackDuckFindings,
} from "./blackduck-findings.js";
import {
  hasVeracodeEvidence,
  normalizeVeracodeFindings,
  veracodeReportRepositories,
} from "./veracode-findings.js";

interface BoundScanner {
  label: string;
  normalize: typeof normalizeInspectorFindings;
  hasEvidence(data: unknown, id: string): boolean;
  repositories: typeof inspectorReportRepositories;
}

export const repositoryBoundScanners: Partial<Record<Provider, BoundScanner>> =
  {
    inspector: {
      label: "Inspector",
      normalize: normalizeInspectorFindings,
      hasEvidence: hasInspectorEvidence,
      repositories: inspectorReportRepositories,
    },
    blackduck: {
      label: "Black Duck",
      normalize: normalizeBlackDuckFindings,
      hasEvidence: hasBlackDuckEvidence,
      repositories: blackDuckReportRepositories,
    },
    veracode: {
      label: "Veracode",
      normalize: normalizeVeracodeFindings,
      hasEvidence: hasVeracodeEvidence,
      repositories: veracodeReportRepositories,
    },
  };

/** Capture the caller's import settings before reading an export or resolving its destination. */
export function snapshotImportOptions<
  P extends ExternalPublicationOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  inspectorProjectMap,
}: ExternalPublicationOptions & { provider: P }) {
  if (inspectorProjectMap !== undefined && provider !== "inspector")
    throw new CodexSecurityError(
      "An Inspector project map requires the inspector provider.",
    );
  return {
    repository,
    provider,
    sourceKey,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}

export function boundScannerRepositories(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
  inspectorProjectMap?: ReadonlyMap<string, string>,
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
    repositoryBoundScanners[provider]?.repositories(
      findings,
      target,
      inspectorProjectMap,
    ) ?? new Map()
  );
}
