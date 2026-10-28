import { createHash } from "node:crypto";
import { dirname, posix } from "node:path";
import type { JsonObject } from "../types.js";
import { artifactSourcePath, type ArtifactContext } from "../artifact-io.js";
import {
  coverageReceiptComponents,
  validateRetainedCoverage,
} from "../coverage-publication.js";
import {
  parsePersistedScanDraft,
  scanDraftInputSchema,
  retainRecordedReceiptOwnership,
  workerCoverageReceiptLocation,
  validateFindingSemantics,
  type ScanDraftInput,
} from "../artifact-scan-draft.js";
import { readJsonObject, requireRegularFile } from "./artifacts.js";
import type { DeepScanArtifacts } from "./artifacts.js";

export type ScanUnion = Omit<ScanDraftInput, "reviewState"> & {
  /** Host-owned accepted coverage, omitted from the legacy persisted reducer format. */
  sourceCoverage?: ScanDraftInput["reviewState"];
};
const aggregateSchema = scanDraftInputSchema.omit({ reviewState: true });

export function scanUnionToDraft(result: ScanUnion): ScanDraftInput {
  const { sourceCoverage, ...draft } = structuredClone(result);
  for (const finding of draft.findings)
    delete finding.provenance.deepScanRepairGroups;
  return { ...draft, reviewState: sourceCoverage ?? unknownSourceCoverage() };
}

/** Keep v1 checkpoints readable by older binaries. */
export function persistedScanUnion(
  result: ScanUnion,
): Omit<ScanDraftInput, "reviewState"> {
  const { sourceCoverage: _coverage, ...persisted } = result;
  return persisted;
}

export function parseScanUnion(input: unknown): ScanUnion {
  const parsed = aggregateSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  if (parsed.complete === false)
    throw new Error("Saved Deep Scan iteration is incomplete.");
  return parsed;
}

/** Admit exactly the complete semantic result written by an ordinary Standard scan. */
export async function validateDiscoveryArtifacts(
  artifacts: DeepScanArtifacts,
  resultPath: string,
  expectedScanId: string,
  boundScope: Pick<
    ArtifactContext,
    "scope" | "includePaths" | "filePaths"
  > = {},
): Promise<ScanDraftInput> {
  await requireRegularFile(resultPath, artifacts.workersRoot);
  const root = dirname(resultPath);
  const context = {
    root,
    repoRoot: root,
    layout: "worker" as const,
    scanId: expectedScanId,
    scope: boundScope.scope,
    includePaths: boundScope.includePaths,
    filePaths: boundScope.filePaths,
  };
  const stored = await readJsonObject(resultPath);
  await retainRecordedReceiptOwnership(context, stored);
  const result = parseStoredScanDraft(
    stored,
    "Standard scan worker",
    expectedScanId,
    parsePersistedScanDraft,
  );
  if (result.complete === false)
    throw new Error(
      "Standard scan worker wrote only a checkpoint; its audit is not complete.",
    );
  validateRetainedCoverage(result.reviewState);
  const receiptPaths = new Map<string, string>();
  for (const row of result.reviewState.surfaces as JsonObject[]) {
    for (const ref of (row.receiptRefs as string[] | undefined) ?? []) {
      const components = coverageReceiptComponents(ref);
      const normalized = components.join("/");
      const key = normalized.toLowerCase();
      const previous = receiptPaths.get(key);
      if (previous !== undefined && previous !== normalized)
        throw new Error(
          `Standard scan worker coverage receipt: duplicate artifact path: ${previous} and ${normalized}`,
        );
      receiptPaths.set(key, normalized);
      const location = workerCoverageReceiptLocation(context, row, ref);
      await artifactSourcePath(
        location.context,
        location.components,
        "Standard scan worker coverage receipt",
      );
    }
  }
  return result;
}

function unknownSourceCoverage(): ScanDraftInput["reviewState"] {
  return {
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  };
}

/** Qualify worker-local IDs and receipt paths before combining accepted coverage. */
export function projectDiscoveryCoverage(
  coverage: ScanDraftInput["reviewState"],
  worker: { id: string; attempt?: number },
  artifactPrefix: string,
  scanReceiptRefs: ReadonlyMap<number, ReadonlySet<string>> = new Map(),
): ScanDraftInput["reviewState"] {
  const archivePrefix = `${posix.dirname(artifactPrefix)}/attempts/`;
  const provenance = {
    workerId: worker.id,
    ...(worker.attempt === undefined ? {} : { attempt: worker.attempt }),
  };
  const prefix = `${worker.id}-attempt-${worker.attempt ?? "unknown"}`;
  const surfaces = coverage.surfaces;
  const surfaceIds = new Map<unknown, string>();
  for (const [index, surface] of surfaces.entries()) {
    if (!surfaceIds.has(surface.id)) {
      surfaceIds.set(surface.id, `${prefix}-surface-${index + 1}`);
    }
  }
  const project = <T extends Record<string, unknown>>(item: T): T => {
    const result = structuredClone(item);
    const descriptions = result.provenance;
    const projected =
      typeof descriptions === "object" &&
      descriptions !== null &&
      !Array.isArray(descriptions)
        ? (descriptions as Record<string, unknown>)
        : {};
    for (const key of [
      "workerId",
      "attempt",
      "sourceId",
      "candidateId",
      "scanReceiptRefs",
    ])
      delete projected[key];
    Object.assign(result, {
      provenance: {
        ...projected,
        ...provenance,
        ...(item.id === undefined ? {} : { sourceId: item.id }),
        ...(item.candidateId === undefined
          ? {}
          : { candidateId: item.candidateId }),
      },
    });
    if (typeof item.candidateId === "string") {
      Object.assign(result, {
        candidateId: `${prefix}-candidate-${createHash("sha256").update(item.candidateId).digest("hex")}`,
      });
    }
    return result;
  };
  return {
    reviews: [provenance],
    surfaces: surfaces.map((surface, index) => ({
      ...project(surface),
      id: `${prefix}-surface-${index + 1}`,
      receiptRefs: ((surface.receiptRefs as string[] | undefined) ?? [])
        .map((ref) => posix.normalize(ref))
        .map((ref) =>
          ref.startsWith(archivePrefix) ||
          ref.startsWith(`${artifactPrefix}/`) ||
          scanReceiptRefs.get(index)?.has(ref)
            ? ref
            : `${artifactPrefix}/${ref}`,
        ),
    })),
    explicitExclusions: coverage.explicitExclusions.map(project),
    deferred: coverage.deferred.map((item, index) => ({
      ...project(item),
      id: `${prefix}-deferred-${index + 1}`,
      ...(item.surfaceIds === undefined
        ? {}
        : {
            surfaceIds: (item.surfaceIds as string[]).map(
              (id) => surfaceIds.get(id) ?? id,
            ),
          }),
    })),
    ...(coverage.resolvedDeferred === undefined
      ? {}
      : {
          resolvedDeferred: coverage.resolvedDeferred.map(({ id, reason }) => ({
            id: `${prefix}-resolved-${id}`,
            reason,
          })),
        }),
    ...(coverage.openQuestions === undefined
      ? {}
      : {
          openQuestions: coverage.openQuestions.map((question) =>
            project(typeof question === "string" ? { question } : question),
          ),
        }),
  };
}

export function parseStoredScanDraft<Result extends ScanUnion>(
  value: Record<string, unknown>,
  label: string,
  expectedScanId: string | undefined,
  parse: (input: Record<string, unknown>) => Result,
  invalidResultMessage = " returned an invalid Standard scan result: ",
  differentScanMessage = " returned a result for a different scan.",
): Result {
  let parsed: Result;
  try {
    parsed = parse(value);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(label + invalidResultMessage + detail, {
      cause: error,
    });
  }
  if (expectedScanId !== undefined && parsed.scanId !== expectedScanId) {
    throw new Error(label + differentScanMessage);
  }
  return parsed;
}
