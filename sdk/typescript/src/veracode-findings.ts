import { z } from "zod";
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
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

const count = z.int().nonnegative();
const positive = z.int().positive();
const pageMetadata = z.object({
  total_elements: count,
  number: count,
  size: positive,
  total_pages: count,
});
const severityByScore = [
  "informational",
  "low",
  "low",
  "medium",
  "high",
  "critical",
] as const;
const applicationGuid = z.guid().toLowerCase();

function integer(value: unknown, label: string, minimum = 0): number {
  const result = (minimum === 0 ? count : positive).safeParse(value);
  if (!result.success)
    throw new Error(
      `Veracode ${label} must be an integer of at least ${minimum}.`,
    );
  return result.data;
}

function guid(value: unknown): string {
  const result = applicationGuid.safeParse(value);
  if (!result.success)
    throw new Error("Expected a Veracode application context GUID.");
  return result.data;
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
): { url: string; scope?: string } | undefined {
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
  const row = record(data["row"], "Veracode retained finding");
  requireApplication(row, scope);
  if (id !== occurrenceId(row, scope))
    throw new Error(
      "Veracode source finding ID contradicts the retained native occurrence.",
    );
  return { url, scope: scope.applicationUrl };
}

export const veracodeReportRepositories = repositoryScopeValidator(
  { provider: "veracode", label: "Veracode", scope: "application" },
  hasVeracodeEvidence,
  retainedRepository,
);

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
  const query = url.searchParams;
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
  const metadata = pageMetadata.safeParse(
    record(document["page"], "Veracode page metadata"),
  );
  if (!metadata.success) {
    const field = metadata.error.issues[0]!.path[0];
    throw new Error(
      `Veracode page.${String(field)} must be an integer of at least ${field === "size" ? 1 : 0}.`,
    );
  }
  const {
    number,
    size,
    total_pages: pages,
    total_elements: total,
  } = metadata.data;
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
  return { rows, scope, query, filter, number, size, total, pages };
}

function severitySelection(query: URLSearchParams, key: string): number | null {
  const values = query.getAll(key);
  if (!values.length) return null;
  if (values.length !== 1 || !/^[0-5]$/u.test(values[0]!))
    throw new Error(`Invalid Veracode ${key} selection.`);
  return Number(values[0]);
}

function readReport(input: unknown) {
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
        page.size !== first.size ||
        page.scope.applicationUrl !== first.scope.applicationUrl ||
        page.filter !== first.filter,
    )
  )
    throw new Error(
      "Supply every Veracode page exactly once with stable totals, selection, origin and application context.",
    );
  const { scope, query } = first;
  const exactSeverity = severitySelection(query, "severity");
  const minimumSeverity = severitySelection(query, "severity_gte");
  const staticOnly = query.has("scan_type");
  const violates = query.get("violates_policy");
  const seen = new Set<string>();
  const rows: Record<string, unknown>[] = [];
  for (const page of pages) {
    for (const value of page.rows) {
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
          throw new Error(
            "Veracode finding contradicts the severity selection.",
          );
      }
      if (staticOnly && row["scan_type"] !== "STATIC")
        throw new Error(
          "Veracode finding contradicts the requested STATIC scan type.",
        );
      if (violates !== null && row["violates_policy"] !== (violates === "true"))
        throw new Error(
          "Veracode finding contradicts the violates_policy selection.",
        );

      const issue = row["issue_id"];
      if (
        typeof row["scan_type"] === "string" &&
        positive.safeParse(issue).success
      ) {
        const key = `${row["scan_type"]}:${issue}`;
        if (seen.has(key))
          throw new Error(
            "Overlapping Veracode findings repeat a native issue; recollect the complete selection.",
          );
        seen.add(key);
      }
      rows.push(row);
    }
  }
  return { scope, rows };
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
  const { scope, rows } = readReport(input);
  return normalizeRecords(
    rows,
    (row) => {
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
      const severity =
        severityByScore[integer(details["severity"], "severity")];
      if (!severity)
        throw new Error("Veracode severity must be on the native 0–5 scale.");
      return validateExternalEvidence(
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
      );
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
