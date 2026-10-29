import { validateHostedRepositoryUrl } from "./hosted-scanner-http.js";
import { CodexSecurityError } from "./errors.js";
import { isRecord } from "./record.js";
import type { ExternalPublicationOptions } from "./external-findings-publish.js";
import type {
  ExternalFindingEvidence,
  Provider,
} from "./external-import-models.js";

/** A provider occurrence and its evidence, independent of a Codex assessment. */
export interface ExternalFinding {
  source_finding_id: string;
  evidence: ExternalFindingEvidence;
}

/** Repository provenance retained by a reader outside the published evidence. */
export interface ExternalSourceRepository {
  url: string;
  platform?: "github";
}

export function snapshotSourceRepositories(
  references: readonly ExternalSourceRepository[] = [],
): ExternalSourceRepository[] {
  return references.map(({ url, platform }) => ({ url, platform }));
}

export interface ExternalFindings {
  read: number;
  /** Reader-retained run metadata, including diagnostics for empty reports. */
  report?: Record<string, unknown>;
  findings: ExternalFinding[];
  excluded: {
    position: number;
    source_finding_id: string | null;
    reason: string;
  }[];
}

/** A Snyk or Semgrep report bound to one source repository, even when it has no findings. */
export interface HostedExternalFindings extends ExternalFindings {
  sourceRepositoryUrl?: string;
  /** "other" requires exact repository path casing on custom hosts. */
  sourceRepositoryPlatform?: "github" | "other";
}

export type NormalizedFindingsFor<P extends Provider> = P extends
  "snyk" | "semgrep"
  ? HostedExternalFindings
  : ExternalFindings;

export const HOSTED_FINDINGS_FORMATS = {
  snyk: "snyk-rest-issues/v1",
  semgrep: "semgrep-platform-findings/v1",
} as const;

/** Retained rows keep their scanner identity even if the report header is projected out. */
export function checkHostedFindingProvider(
  provider: Provider,
  data: ExternalFindingEvidence["source_data"],
): void {
  const format = data?.["format"];
  const native =
    format === HOSTED_FINDINGS_FORMATS.snyk
      ? "snyk"
      : format === HOSTED_FINDINGS_FORMATS.semgrep
        ? "semgrep"
        : undefined;
  if (native && native !== provider)
    throw new CodexSecurityError(
      `Retained ${native} evidence requires the ${native} provider.`,
    );
}

/** Capture the public SDK fields once, including class accessors, before any asynchronous work. */
export function snapshotExternalFindings(
  input: HostedExternalFindings,
  provider: Provider,
): HostedExternalFindings {
  const {
    read,
    findings,
    excluded,
    report,
    sourceRepositoryUrl,
    sourceRepositoryPlatform,
    ...rest
  } = input;
  if (
    (sourceRepositoryUrl !== undefined ||
      sourceRepositoryPlatform !== undefined) &&
    provider !== "snyk" &&
    provider !== "semgrep"
  )
    throw new CodexSecurityError(
      "Normalized report repository declarations require the Snyk or Semgrep provider.",
    );
  if (typeof sourceRepositoryUrl === "string")
    validateHostedRepositoryUrl(sourceRepositoryUrl);
  const current: HostedExternalFindings = structuredClone({
    ...rest,
    read,
    findings,
    excluded,
    ...((sourceRepositoryUrl !== undefined ||
      "sourceRepositoryUrl" in input) && { sourceRepositoryUrl }),
    ...((sourceRepositoryPlatform !== undefined ||
      "sourceRepositoryPlatform" in input) && { sourceRepositoryPlatform }),
  });
  // Report metadata may alias evidence that receives Cloud defaults.
  if (report !== undefined) current.report = structuredClone(report);
  const context = current.report?.["snyk_rest_context"];
  if (isRecord(context) && context["format"] === HOSTED_FINDINGS_FORMATS.snyk)
    checkHostedFindingProvider(provider, context);
  return current;
}

/** @internal Keep earlier provider projections only for immutable request replay. */
export interface ExternalPublicationInput {
  current: HostedExternalFindings;
  legacy: HostedExternalFindings;
  currentIdentity: unknown;
  legacyIdentity: unknown;
}

/** Capture the caller's import settings before reading an export or resolving its destination. */
export function snapshotImportOptions<
  P extends ExternalPublicationOptions["provider"],
>({
  repository,
  provider,
  sourceKey,
  sourceRepositoryUrl,
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
    sourceRepositoryUrl,
    inspectorProjectMap: inspectorProjectMap && new Map(inspectorProjectMap),
  };
}
