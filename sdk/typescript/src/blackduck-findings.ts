import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";

import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

export function blackDuckEvidenceRepositoryUrls(
  sourceData: unknown,
  expectedSourceFindingId?: string,
): string[] {
  if (!isRecord(sourceData)) return [];
  const row = sourceData["row"];
  const recognized =
    "projectVersionUrl" in sourceData ||
    (isRecord(row) && "vulnerabilityWithRemediation" in row) ||
    ("componentVersion" in sourceData &&
      "vulnerabilityWithRemediation" in sourceData);
  if (!("sourceRepositoryUrl" in sourceData) && !recognized) return [];
  const repository = declaredScannerRepositoryUrl(
    sourceData["sourceRepositoryUrl"],
    "Black Duck",
  );
  if (recognized) {
    const resource = apiResource(
      sourceData["projectVersionUrl"],
      "retained project-version URL",
    );
    if (
      !/^projects\/[^/]+\/versions\/[^/]+$/u.test(resource.path) ||
      resource.query.size
    )
      throw new Error("Invalid retained Black Duck project-version URL.");
    const scope = `${resource.base}/${resource.path}`;
    const actual = occurrenceId(scopedRow(row, scope, false), scope);
    if (
      expectedSourceFindingId !== undefined &&
      expectedSourceFindingId !== actual
    )
      throw new Error(
        "Black Duck source finding ID contradicts the retained native occurrence.",
      );
  }
  return [repository];
}

function apiResource(href: unknown, label: string) {
  const url = URL.parse(requiredText(href, label));
  const parts = url && /^(.*\/api)\/(.+?)\/?$/u.exec(url.pathname);
  if (
    !url ||
    !parts ||
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash
  )
    throw new Error(
      `Expected a credential-free Black Duck API URL for ${label}.`,
    );
  return {
    base: url.origin + parts[1],
    path: parts[2]!,
    query: url.searchParams,
  };
}

function links(meta: unknown): Record<string, unknown>[] {
  if (meta === undefined) return [];
  const value = record(meta, "Black Duck _meta")["links"];
  return value === undefined
    ? []
    : array(value, "Black Duck _meta.links").map((entry) =>
        record(entry, "Black Duck link"),
      );
}

function collectionScope(collection: Record<string, unknown>) {
  const meta = record(collection["_meta"], "Black Duck collection _meta");
  const resource = apiResource(meta["href"], "collection href");
  const project =
    /^projects?\/([^/]+)\/versions\/([^/]+)\/vulnerable-bom-components$/u.exec(
      resource.path,
    );
  if (!project)
    throw new Error(
      "Expected a Black Duck project-version vulnerable-bom-components collection.",
    );
  if (
    resource.query.getAll("offset").some((offset) => !/^0+$/u.test(offset)) ||
    links(meta).some((link) =>
      ["next", "prev", "previous"].includes(String(link["rel"])),
    )
  )
    throw new Error(
      "Incomplete Black Duck collection page. Supply a complete export or explicitly selected rows.",
    );
  return `${resource.base}/projects/${project[1]}/versions/${project[2]}`;
}

function matchedFile(href: unknown) {
  const resource = apiResource(href, "matched-files link");
  const match =
    /^(projects\/[^/]+\/versions\/[^/]+)\/(components\/[^/]+\/versions\/[^/]+)\/origins\/([^/]+)\/matched-files$/u.exec(
      resource.path,
    );
  if (!match)
    throw new Error("Invalid Black Duck project-version matched-files link.");
  return {
    scope: `${resource.base}/${match[1]}`,
    component: `${resource.base}/${match[2]}`,
    origin: match[3]!,
  };
}

function scopedRow(
  value: unknown,
  scope: string | undefined,
  selected: boolean,
) {
  const metadata = isRecord(value) ? links(value["_meta"]) : [];
  const matched = metadata
    .filter((link) => link["rel"] === "matched-files")
    .map((link) => matchedFile(link["href"]));
  if (selected && !matched.length)
    throw new Error(
      "Each selected Black Duck row must identify its project version with a matched-files link.",
    );
  for (const reference of matched) {
    if (scope !== undefined && scope !== reference.scope)
      throw new Error(
        "Black Duck rows must belong to the same project version and server as the collection or selection.",
      );
    scope = reference.scope;
  }
  return { value, matched, metadata, scope };
}

function occurrenceId(
  { value, matched, metadata }: ReturnType<typeof scopedRow>,
  projectVersion: string,
) {
  const row = record(value, "Black Duck BOM component");
  const vulnerability = record(
    row["vulnerabilityWithRemediation"],
    "Black Duck vulnerabilityWithRemediation",
  );
  const resource = apiResource(row["componentVersion"], "componentVersion");
  const component = `${resource.base}/${resource.path}`;
  if (
    !/^components\/[^/]+\/versions\/[^/]+$/u.test(resource.path) ||
    resource.base !==
      projectVersion.slice(0, projectVersion.lastIndexOf("/projects/"))
  )
    throw new Error(
      "Black Duck componentVersion must identify a component version on the same server.",
    );
  const origins = new Set<string>();
  for (const reference of matched) {
    if (reference.component !== component)
      throw new Error(
        "Black Duck matched-files link contradicts componentVersion.",
      );
    origins.add(reference.origin);
  }
  for (const link of metadata.filter(
    (entry) => entry["rel"] === "vulnerabilities",
  )) {
    const reference = apiResource(link["href"], "vulnerabilities link");
    const match =
      /^(components\/[^/]+\/versions\/[^/]+)\/origin\/([^/]+)\/vulnerabilities$/u.exec(
        reference.path,
      );
    if (!match) continue;
    if (`${reference.base}/${match[1]}` !== component)
      throw new Error(
        "Black Duck vulnerabilities link contradicts componentVersion.",
      );
    origins.add(match[2]!);
  }
  const [origin] = origins;
  if (!origin || origins.size !== 1)
    throw new Error(
      "Black Duck row must identify one unambiguous component-version origin.",
    );
  const source = requiredText(
    vulnerability["source"],
    "Black Duck advisory source",
  );
  if (source !== "BDSA" && source !== "NVD")
    throw new Error(`Unsupported Black Duck advisory source: ${source}.`);
  return stableId("blackduck-bom", [
    projectVersion,
    component,
    origin,
    requiredText(row["componentVersionOriginName"], "Black Duck origin name"),
    requiredText(row["componentVersionOriginId"], "Black Duck origin ID"),
    source,
    requiredText(
      vulnerability["vulnerabilityName"],
      "Black Duck vulnerability name",
    ),
  ]);
}

export function normalizeBlackDuckFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Black Duck",
  );
  const selected = Array.isArray(input);
  let scope: string | undefined;
  let items: unknown[];
  if (selected) {
    items = input;
  } else {
    const collection = record(input, "Black Duck collection");
    items = array(collection["items"], "Black Duck items");
    scope = collectionScope(collection);
    if (collection["totalCount"] !== items.length)
      throw new Error(
        "Incomplete Black Duck collection: totalCount must equal the number of items. Supply a complete export or explicitly selected rows.",
      );
  }

  const rows = items.map((value) => {
    const entry = scopedRow(value, scope, selected);
    scope = entry.scope;
    return entry;
  });
  if (!scope)
    throw new Error(
      "An empty Black Duck selection cannot identify a project version. Supply its complete collection envelope.",
    );
  const projectVersion = scope;
  return normalizeRecords(
    rows,
    ({ value }, id) => {
      const row = record(value, "Black Duck BOM component");
      const vulnerability = record(
        row["vulnerabilityWithRemediation"],
        "Black Duck vulnerabilityWithRemediation",
      );
      const advisory = requiredText(
        vulnerability["vulnerabilityName"],
        "Black Duck vulnerability name",
      );
      const name = requiredText(
        row["componentName"],
        "Black Duck component name",
      );
      const severity = text(vulnerability["severity"])?.toLowerCase();
      return {
        source_finding_id: id,
        evidence: validateExternalEvidence(
          {
            title: `${advisory} in ${name}`,
            description: text(vulnerability["description"]),
            severity:
              severity &&
              ["critical", "high", "medium", "low"].includes(severity)
                ? severity
                : "unknown",
            advisory_ids: [advisory],
            packages: [
              {
                name,
                ecosystem: text(row["componentVersionOriginName"]),
                installed_version: text(row["componentVersionName"]),
              },
            ],
            source_data: structuredClone({
              sourceRepositoryUrl: repository,
              projectVersionUrl: projectVersion,
              row,
            }),
          },
          target,
        ),
      };
    },
    (entry) => occurrenceId(entry, projectVersion),
    target,
    selected ? "exclude" : "reject",
  );
}

export async function readBlackDuckFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeBlackDuckFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
