import { CodexSecurityError } from "./errors.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  type ExternalImportTarget,
} from "./external-import-contract.js";
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
  blackDuckEvidenceRepositoryUrls,
  readBlackDuckFindings,
} from "./blackduck-findings.js";

export const repositoryBoundScanners: Partial<
  Record<Provider, { read: typeof readInspectorFindings }>
> = {
  inspector: { read: readInspectorFindings },
  blackduck: { read: readBlackDuckFindings },
};

export function boundScannerRepositories(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
): Map<string, ExternalSourceRepository> {
  if (provider === "inspector")
    return inspectorReportRepositories(findings, target);
  if (findings.some(({ evidence }) => hasInspectorEvidence(evidence.source_data)))
    throw new CodexSecurityError(
      "Retained Inspector evidence requires the inspector provider.",
    );
  const repositories = new Map<string, ExternalSourceRepository>();
  if (provider === "blackduck") {
    const key = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
    for (const { source_finding_id: id, evidence } of findings) {
      const [url] = blackDuckEvidenceRepositoryUrls(evidence.source_data, id);
      if (!url) continue;
      const declared = evidence.details?.repository?.url;
      if (declared && key(declared) !== key(url))
        throw new CodexSecurityError(
          "Retained scanner repository does not match the normalized evidence repository.",
        );
      repositories.set(id, { url });
    }
  }
  return repositories;
}
