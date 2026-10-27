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

export function veracodeEvidenceRepositoryUrls(
  sourceData: unknown,
  expectedSourceFindingId?: string,
): string[] {
  if (!isRecord(sourceData)) return [];
  const row = sourceData["row"];
  const recognized =
    "applicationUrl" in sourceData ||
    (isRecord(row) && "context_guid" in row) ||
    ("context_guid" in sourceData && "issue_id" in sourceData);
  if (!("sourceRepositoryUrl" in sourceData) && !recognized) return [];
  const repository = declaredScannerRepositoryUrl(
    sourceData["sourceRepositoryUrl"],
    "Veracode",
  );
  if (recognized) {
    const scope = applicationScope(
      halUrl({ href: sourceData["applicationUrl"] }, "retained application"),
    );
    const finding = record(row, "Veracode retained finding");
    const actual = occurrenceId(finding, scope);
    if (
      expectedSourceFindingId !== undefined &&
      expectedSourceFindingId !== actual
    )
      throw new Error(
        "Veracode source finding ID contradicts the retained native occurrence.",
      );
  }
  return [repository];
}

function selection(url: URL, scope: Scope, number: number, size: number) {
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
        : key === "page" && number !== 0
    )
      throw new Error(`Veracode HAL ${key} does not match the declared page.`);
    query.delete(key);
  }
  query.sort();
  return query;
}

function readPage(input: unknown) {
  const document = record(input, "Veracode HAL findings page");
  const embedded = record(document["_embedded"], "Veracode HAL _embedded");
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
  const page = record(document["page"], "Veracode page metadata");
  const number = integer(page["number"], "page.number");
  const size = integer(page["size"], "page.size", 1);
  const total = integer(page["total_elements"], "page.total_elements");
  const pages = integer(page["total_pages"], "page.total_pages");
  if (
    !(pages === Math.ceil(total / size) || (total === 0 && pages === 1)) ||
    number >= Math.max(1, pages) ||
    rows.length !== Math.min(size, total - number * size)
  )
    throw new Error("Incomplete or inconsistent Veracode HAL page counts.");
  const links = record(document["_links"], "Veracode HAL _links");
  const scope = applicationScope(halUrl(links["application"], "application"));
  const query = selection(halUrl(links["self"], "self"), scope, number, size);
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
        selection(halUrl(link, rel), scope, position, size).toString() !==
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
  for (const value of rows) {
    const row = record(value, "Veracode finding");
    requireApplication(row, scope);
    if (query.has("scan_type") && row["scan_type"] !== "STATIC")
      throw new Error(
        "Veracode finding contradicts the requested STATIC scan type.",
      );
    const violates = query.get("violates_policy");
    if (
      violates !== null &&
      row["violates_policy"] !== (violates.toLowerCase() === "true")
    )
      throw new Error(
        "Veracode finding contradicts the violates_policy selection.",
      );
  }
  return { rows, scope, filter, number, size, total, pages };
}

export function normalizeVeracodeFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Veracode",
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
  if (pages.length > 1) {
    const seen = new Map<number, number>();
    for (const page of pages) {
      for (const value of page.rows) {
        const row = record(value, "Veracode finding");
        const issue = row["issue_id"];
        if (
          row["scan_type"] !== "STATIC" ||
          typeof issue !== "number" ||
          !Number.isSafeInteger(issue) ||
          issue <= 0
        )
          continue;
        const previous = seen.get(issue);
        if (previous !== undefined && previous !== page.number)
          throw new Error(
            "Overlapping Veracode pages repeat a native issue; recollect the complete selection.",
          );
        seen.set(issue, page.number);
      }
    }
  }
  return normalizeRecords(
    pages.flatMap((page) => page.rows),
    (value, id) => {
      const row = record(value, "Veracode finding");
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
    (value) => {
      const row = record(value, "Veracode finding");
      return occurrenceId(row, scope);
    },
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
