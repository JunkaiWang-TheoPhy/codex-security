import {
  type ExternalImportTarget,
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
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

const format = "blackduck-bom-6";
const nativeId = /^blackduck-bom:[a-f0-9]{64}$/u;

export function hasBlackDuckEvidence(data: unknown): boolean {
  if (!isRecord(data)) return false;
  const row = data["row"];
  return (
    data["format"] === format ||
    ("vulnerabilityWithRemediation" in data && "componentVersion" in data) ||
    (isRecord(row) &&
      "vulnerabilityWithRemediation" in row &&
      "componentVersion" in row)
  );
}

function retainedRepository(
  data: unknown,
  id: string | undefined,
  target: ExternalImportTarget,
): { url: string; projectVersion?: string } | undefined {
  const native =
    hasBlackDuckEvidence(data) || (id !== undefined && nativeId.test(id));
  if (native && (!isRecord(data) || !isRecord(data["row"])))
    throw new Error("Expected retained Black Duck BOM occurrence evidence.");
  if (!isRecord(data) || (!native && !("sourceRepositoryUrl" in data))) return;
  const url = declaredScannerRepositoryUrl(
    data["sourceRepositoryUrl"],
    "Black Duck",
    target,
  );
  if (!native) return { url };
  const resource = apiResource(
    data["projectVersionUrl"],
    "retained project-version URL",
  );
  if (
    !/^projects\/[^/]+\/versions\/[^/]+$/u.test(resource.path) ||
    resource.query.size
  )
    throw new Error("Invalid retained Black Duck project-version URL.");
  const projectVersion = `${resource.base}/${resource.path}`;
  const actual = occurrenceId(
    scopedRow(data["row"], projectVersion, false),
    projectVersion,
  );
  if (id !== undefined && id !== actual)
    throw new Error(
      "Black Duck source finding ID contradicts the retained native occurrence.",
    );
  return { url, projectVersion };
}

export function blackDuckEvidenceRepositoryUrls(
  data: unknown,
  id?: string,
  target: ExternalImportTarget = "cloud",
): string[] {
  const retained = retainedRepository(data, id, target);
  return retained ? [retained.url] : [];
}

export function blackDuckReportRepositories(
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
): Map<string, ExternalSourceRepository> {
  const repositories = new Map<string, ExternalSourceRepository>();
  const key = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
  let scope: string | undefined;
  let repository: string | undefined;
  for (const { source_finding_id: id, evidence } of findings) {
    const retained = retainedRepository(evidence.source_data, id, target);
    if (!retained) continue;
    if (retained.projectVersion) {
      if (
        scope &&
        (scope !== retained.projectVersion || repository !== key(retained.url))
      )
        throw new Error(
          "Black Duck occurrences must belong to the same project version and source repository.",
        );
      scope = retained.projectVersion;
      repository = key(retained.url);
    }
    const declared = evidence.details?.repository?.url;
    if (declared && key(declared) !== key(retained.url))
      throw new Error(
        "Retained scanner repository does not match the normalized evidence repository.",
      );
    repositories.set(id, { url: retained.url });
  }
  return repositories;
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

function projectReference(href: unknown, remediation: boolean) {
  const label = remediation ? "remediation URL" : "matched-files link";
  const resource = apiResource(href, label);
  const path = remediation
    ? /^(projects\/[^/]+\/versions\/[^/]+)\/(components\/[^/]+\/versions\/[^/]+)(?:\/origins\/([^/]+))?\/vulnerabilities\/[^/]+\/remediation$/u
    : /^(projects\/[^/]+\/versions\/[^/]+)\/(components\/[^/]+\/versions\/[^/]+)(?:\/origins\/([^/]+))?\/matched-files$/u;
  const match = path.exec(resource.path);
  if (!match) throw new Error(`Invalid Black Duck project-version ${label}.`);
  return {
    scope: `${resource.base}/${match[1]}`,
    component: `${resource.base}/${match[2]}`,
    origin: match[3],
  };
}

function scopedRow(
  value: unknown,
  scope: string | undefined,
  selected: boolean,
) {
  const meta = isRecord(value) ? value["_meta"] : undefined;
  const metadata = links(meta);
  const matched = metadata
    .filter((link) => link["rel"] === "matched-files")
    .map((link) => projectReference(link["href"], false));
  if (isRecord(meta) && meta["href"] !== undefined)
    matched.push(projectReference(meta["href"], true));
  if (selected && !matched.length)
    throw new Error(
      "Each selected Black Duck row must identify its project version with a remediation or matched-files link.",
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
        "Black Duck project-version link contradicts componentVersion.",
      );
    if (reference.origin) origins.add(reference.origin);
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
    source,
    requiredText(
      vulnerability["vulnerabilityName"],
      "Black Duck vulnerability name",
    ),
  ]);
}

const nameVersionForges = new Map([
  ["npmjs", "npm"],
  ["pypi", "pypi"],
  ["nuget", "nuget"],
  ["rubygems", "gem"],
  ["crates", "cargo"],
]);

function blackDuckPackages(row: Record<string, unknown>) {
  const version = text(row["componentVersionName"]);
  const purl =
    /^pkg:([a-z][a-z0-9.+-]*)\/([^@?#]+)(?:@([^@?#]+))?(?:[?#].*)?$/iu.exec(
      text(row["packageUrl"]) ?? "",
    );
  if (purl) {
    try {
      const ecosystem = purl[1]!.toLowerCase();
      const parts = purl[2]!.split("/").map(decodeURIComponent);
      const name = parts.pop()!;
      const installed_version = purl[3] ? decodeURIComponent(purl[3]) : version;
      if (name && !parts.includes("")) {
        if (ecosystem === "maven" && parts.length === 1)
          return [
            { name: `${parts[0]}:${name}`, ecosystem, installed_version },
          ];
        if (
          ecosystem === "npm" &&
          parts.length === 1 &&
          parts[0]!.startsWith("@")
        )
          return [
            { name: `${parts[0]}/${name}`, ecosystem, installed_version },
          ];
        if (parts.length === 0 && ecosystem !== "maven")
          return [{ name, ecosystem, installed_version }];
      }
    } catch {
      // A malformed escape does not invalidate the native origin coordinate.
    }
  }

  const origin = text(row["componentVersionOriginName"])?.toLowerCase();
  const id = text(row["componentVersionOriginId"]) ?? "";
  if (origin === "maven") {
    const coordinate = /^([^:\s/]+:[^:\s/]+):([^:\s/]+)$/u.exec(id);
    if (coordinate)
      return [
        {
          name: coordinate[1]!,
          ecosystem: origin,
          installed_version: coordinate[2]!,
        },
      ];
  }
  const ecosystem = nameVersionForges.get(origin ?? "");
  if (ecosystem) {
    const coordinate = /^(?:(@[^/\s]+)\/)?([^/\s]+)\/([^/\s]+)$/u.exec(id);
    if (coordinate && (!coordinate[1] || ecosystem === "npm"))
      return [
        {
          name: id.slice(0, id.lastIndexOf("/")),
          ecosystem,
          installed_version: coordinate[3]!,
        },
      ];
  }
  return [];
}

export function normalizeBlackDuckFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Black Duck",
    target,
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
      const related = text(vulnerability["relatedVulnerability"]);
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
            advisory_ids:
              related && related !== advisory
                ? [advisory, related]
                : [advisory],
            packages: blackDuckPackages(row),
            source_data: structuredClone({
              format,
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
