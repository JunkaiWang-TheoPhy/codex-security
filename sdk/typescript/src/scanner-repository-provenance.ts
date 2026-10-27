import { CodexSecurityError } from "./errors.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { Provider } from "./external-import-models.js";
import {
  hasInspectorEvidence,
  inspectorReportRepositories,
} from "./inspector-findings.js";

export function boundScannerRepositories(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
): Map<string, ExternalSourceRepository> {
  if (provider === "inspector")
    return inspectorReportRepositories(findings, target);
  if (
    findings.some(({ evidence }) => hasInspectorEvidence(evidence.source_data))
  )
    throw new CodexSecurityError(
      "Retained Inspector evidence requires the inspector provider.",
    );
  return new Map();
}
