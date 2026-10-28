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

function integer(value: unknown, label: string, minimum = 0): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum
  )
    throw new Error(
      `Veracode ${label} must be an integer of at least ${minimum}.`,
    );
  return value;
}

function guid(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/iu.test(value)
  )
    throw new Error("Expected a Veracode application context GUID.");
  return value.toLowerCase();
}

function halUrl(value: unknown, label: string): URL {
  const link = record(value, `Veracode ${label} link`);
  const href = requiredText(link["href"], `Veracode ${label} href`);
  const template =
    link["templated"] === true && /\{([?&])[\w]+(?:,[\w]+)*\}$/u.exec(href);
  const concrete = template ? href.slice(0, template.index) : href;
  const parts = /^https?:\/\/([^/?#\\]+)(\/[^?#]*)(?:\?[^#]*)?$/iu.exec(
    concrete,
  );
  const url = URL.parse(concrete);
  if (
    !url ||
    !parts ||
    (template && (template[1] === "&") !== concrete.includes("?")) ||
    parts[1]!.includes("@") ||
    url.username ||
    url.password ||
    /[{}\\\s\p{Cc}]/u.test(concrete) ||
    parts[2] !== url.pathname
  )
    throw new Error(`Invalid Veracode ${label} HAL URL.`);
  return url;
}

function applicationScope(url: URL) {
  const match = /^\/appsec\/v1\/applications\/([^/]+)$/u.exec(url.pathname);
  if (!match || url.href.includes("?"))
    throw new Error(
      "Expected a Veracode application HAL URL without query parameters.",
    );
  const application = guid(match[1]);
  return {
    origin: url.origin,
    application,
    applicationUrl: `${url.origin}/appsec/v1/applications/${application}`,
  };
}

type Scope = ReturnType<typeof applicationScope>;

function requireApplication(row: Record<string, unknown>, scope: Scope) {
  if (
    row["context_type"] !== "APPLICATION" ||
    guid(row["context_guid"]) !== scope.application
  )
    throw new Error(
      "Veracode findings must belong to the same APPLICATION policy context; sandbox and mixed applications are unsupported.",
    );
}

function occurrenceId(row: Record<string, unknown>, scope: Scope): string {
  requireApplication(row, scope);
  if (row["scan_type"] !== "STATIC")
    throw new Error("Only Veracode STATIC findings are supported.");
  return stableId("veracode-static-policy", [
    scope.origin,
    scope.application,
    row["context_type"],
    scope.application,
    integer(row["issue_id"], "issue_id", 1),
  ]);
}

export function hasVeracodeEvidence(data: unknown, id: string): boolean {
  if (/^veracode-static-policy:[a-f0-9]{64}$/u.test(id)) return true;
  if (!isRecord(data)) return false;
  const row = isRecord(data["row"]) ? data["row"] : data;
  return (
    "context_guid" in row &&
    "context_type" in row &&
    "scan_type" in row &&
    "issue_id" in row
  );
}

function retainedRepository(
  sourceData: unknown,
  id: string,
  target: ExternalImportTarget,
): { url: string; applicationUrl?: string } | undefined {
  const data = isRecord(sourceData) ? sourceData : {};
  const native = hasVeracodeEvidence(data, id);
  if (!native && !("sourceRepositoryUrl" in data)) return;
  const url = declaredScannerRepositoryUrl(
    data["sourceRepositoryUrl"],
    "Veracode",
    target,
  );
  if (!native) return { url };
  const scope = applicationScope(
    halUrl({ href: data["applicationUrl"] }, "retained application"),
  );
  const actual = occurrenceId(
    record(data["row"], "Veracode retained finding"),
    scope,
  );
  if (id !== actual)
    throw new Error(
      "Veracode source finding ID contradicts the retained native occurrence.",
    );
  return { url, applicationUrl: scope.applicationUrl };
}

export function veracodeReportRepositories(
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
): Map<string, ExternalSourceRepository> {
  const repositories = new Map<string, ExternalSourceRepository>();
  const key = target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
  let scope: { applicationUrl: string; repositoryKey: string } | undefined;
  for (const { source_finding_id: id, evidence } of findings) {
    const retained = retainedRepository(evidence.source_data, id, target);
    if (!retained) continue;
    const repositoryKey = key(retained.url);
    const declared = evidence.details?.repository?.url;
    if (declared && key(declared) !== repositoryKey)
      throw new Error(
        "Retained scanner repository does not match the normalized evidence repository.",
      );
    if (retained.applicationUrl) {
      if (
        scope &&
        (scope.applicationUrl !== retained.applicationUrl ||
          scope.repositoryKey !== repositoryKey)
      )
        throw new Error(
          "Veracode occurrences must belong to the same application and source repository.",
        );
      scope = { applicationUrl: retained.applicationUrl, repositoryKey };
    }
    repositories.set(id, { url: retained.url });
  }
  return repositories;
}

function selection(
  url: URL,
  scope: Scope,
  number: number,
  size: number,
  rel: string,
) {
  const match = /^\/appsec\/v2\/applications\/([^/]+)\/findings$/u.exec(
    url.pathname,
  );
  if (
    url.origin !== scope.origin ||
    !match ||
    guid(match[1]) !== scope.application
  )
    throw new Error(
      "Veracode HAL links must identify the same origin and findings application.",
    );
  const query = new URLSearchParams(url.search);
  const scans = query.getAll("scan_type");
  if (
    query.has("context") ||
    scans.length > 1 ||
    scans.some((type) => type !== "STATIC")
  )
    throw new Error(
      "Only the Veracode STATIC APPLICATION policy selection is supported, not sandbox, DAST or SCA.",
    );
  const violating = query.getAll("violates_policy");
  if (
    violating.length > 1 ||
    violating.some((flag) => !/^(true|false)$/iu.test(flag))
  )
    throw new Error("Invalid Veracode violates_policy selection.");
  if (violating[0]) query.set("violates_policy", violating[0].toLowerCase());
  for (const [key, expected] of [
    ["page", number],
    ["size", size],
  ] as const) {
    const values = query.getAll(key);
    if (
      values.length
        ? values.length !== 1 || values[0] !== String(expected)
        : key === "page" && number !== 0 && rel !== "self"
    )
      throw new Error(`Veracode HAL ${key} does not match the declared page.`);
    query.delete(key);
  }
  query.sort();
  return query;
}

function readPage(input: unknown) {
  const document = record(input, "Veracode HAL findings page");
  const page = record(document["page"], "Veracode page metadata");
  const total = integer(page["total_elements"], "page.total_elements");
  const embedded =
    document["_embedded"] === undefined && total === 0
      ? { findings: [] }
      : record(document["_embedded"], "Veracode HAL _embedded");
  if (
    document["error"] != null ||
    (document["status"] != null && document["status"] !== 200) ||
    [document["errors"], embedded["errors"]].some(
      (errors) =>
        errors != null && !(Array.isArray(errors) && errors.length === 0),
    )
  )
    throw new Error(
      "Veracode returned an error, not a complete findings page.",
    );
  const rows = array(embedded["findings"], "Veracode _embedded.findings");
  const number = integer(page["number"], "page.number");
  const size = integer(page["size"], "page.size", 1);
  const pages = integer(page["total_pages"], "page.total_pages");
  if (
    !(pages === Math.ceil(total / size) || (total === 0 && pages === 1)) ||
    number >= Math.max(1, pages) ||
    rows.length !== Math.min(size, total - number * size)
  )
    throw new Error("Incomplete or inconsistent Veracode HAL page counts.");
  const links = record(document["_links"], "Veracode HAL _links");
  const scope = applicationScope(halUrl(links["application"], "application"));
  const query = selection(
    halUrl(links["self"], "self"),
    scope,
    number,
    size,
    "self",
  );
  const filter = query.toString();
  const positions: Record<string, number> = {
    first: 0,
    last: Math.max(0, pages - 1),
    next: number + 1,
    prev: number - 1,
    previous: number - 1,
  };
  for (const [rel, link] of Object.entries(links)) {
    if (rel === "application" || rel === "self") continue;
    if (Object.hasOwn(positions, rel)) {
      const position = positions[rel]!;
      if (
        position < 0 ||
        position >= Math.max(1, pages) ||
        selection(halUrl(link, rel), scope, position, size, rel).toString() !==
          filter
      )
        throw new Error(
          `Contradictory Veracode ${rel} page link or selection.`,
        );
    } else {
      for (const reference of Array.isArray(link) ? link : [link]) {
        const url = halUrl(reference, rel);
        const app = /^\/appsec\/v[12]\/applications\/([^/]+)/u.exec(
          url.pathname,
        );
        if (
          url.origin !== scope.origin ||
          (app && guid(app[1]) !== scope.application)
        )
          throw new Error(
            `Veracode ${rel} link contradicts the origin or application.`,
          );
      }
    }
  }
  const exactSeverity = severitySelection(query, "severity");
  const minimumSeverity = severitySelection(query, "severity_gte");
  const violates = query.get("violates_policy");
  const findings = Array.from(rows, (value) => {
    const row = record(value, "Veracode finding");
    requireApplication(row, scope);
    if (exactSeverity !== null || minimumSeverity !== null) {
      const details = record(
        row["finding_details"],
        "Veracode finding_details",
      );
      const severity = integer(details["severity"], "severity");
      if (
        (exactSeverity !== null && severity !== exactSeverity) ||
        (minimumSeverity !== null && severity < minimumSeverity)
      )
        throw new Error("Veracode finding contradicts the severity selection.");
    }
    if (query.has("scan_type") && row["scan_type"] !== "STATIC")
      throw new Error(
        "Veracode finding contradicts the requested STATIC scan type.",
      );
    if (violates !== null && row["violates_policy"] !== (violates === "true"))
      throw new Error(
        "Veracode finding contradicts the violates_policy selection.",
      );
    return row;
  });
  return { findings, scope, filter, number, size, total, pages };
}

function severitySelection(query: URLSearchParams, key: string): number | null {
  const values = query.getAll(key);
  if (!values.length) return null;
  if (values.length !== 1 || !/^[0-5]$/u.test(values[0]!))
    throw new Error(`Invalid Veracode ${key} selection.`);
  return Number(values[0]);
}

export function normalizeVeracodeFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Veracode",
    target,
  );
  const pages = (Array.isArray(input) ? input : [input])
    .map(readPage)
    .sort((left, right) => left.number - right.number);
  const first = pages[0];
  if (
    !first ||
    pages.length !== Math.max(1, first.pages) ||
    pages.some(
      (page, index) =>
        page.number !== index ||
        page.total !== first.total ||
        page.pages !== first.pages ||
        page.size !== first.size ||
        page.scope.applicationUrl !== first.scope.applicationUrl ||
        page.filter !== first.filter,
    )
  )
    throw new Error(
      "Supply every Veracode page exactly once with stable totals, selection, origin and application context.",
    );
  const { scope } = first;
  const rows = pages.flatMap((page) => page.findings);
  const seen = new Set<string>();
  for (const row of rows) {
    const issue = row["issue_id"];
    if (
      typeof row["scan_type"] !== "string" ||
      typeof issue !== "number" ||
      !Number.isSafeInteger(issue) ||
      issue <= 0
    )
      continue;
    const key = `${row["scan_type"]}:${issue}`;
    if (seen.has(key))
      throw new Error(
        "Overlapping Veracode findings repeat a native issue; recollect the complete selection.",
      );
    seen.add(key);
  }
  return normalizeRecords(
    rows,
    (row, id) => {
      const details = record(
        row["finding_details"],
        "Veracode finding_details",
      );
      const status = record(row["finding_status"], "Veracode finding_status");
      const cwe = record(details["cwe"], "Veracode CWE");
      const weakness = `CWE-${integer(cwe["id"], "CWE ID", 1)}`;
      const category =
        details["finding_category"] == null
          ? null
          : record(details["finding_category"], "Veracode finding category");
      const severity = [
        "informational",
        "low",
        "low",
        "medium",
        "high",
        "critical",
      ][integer(details["severity"], "severity")];
      if (!severity)
        throw new Error("Veracode severity must be on the native 0–5 scale.");
      return {
        source_finding_id: id,
        evidence: validateExternalEvidence(
          {
            title: text(category?.["name"]) ?? text(cwe["name"]) ?? weakness,
            severity,
            description: text(row["description"]),
            details: {
              kind: "sast",
              repository: { url: repository },
              source_status: requiredText(
                status["status"],
                "Veracode finding status",
              ),
              weakness_ids: [weakness],
            },
            source_data: structuredClone({
              sourceRepositoryUrl: repository,
              applicationUrl: scope.applicationUrl,
              row,
            }),
          },
          target,
        ),
      };
    },
    (row) => occurrenceId(row, scope),
    target,
    "reject",
  );
}

export async function readVeracodeFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeVeracodeFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
