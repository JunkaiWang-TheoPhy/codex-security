import { hash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";

export function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

export function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value;
}

export function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function requiredText(value: unknown, label: string): string {
  const result = text(value);
  if (!result) throw new Error(`${label} must be nonempty text.`);
  return result;
}

export function scannerSeverity(value: string | null | undefined): string {
  return value && ["critical", "high", "medium", "low"].includes(value)
    ? value
    : "unknown";
}

export function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => text(v) !== null)
    : [];
}

/** Paths that cannot be attributed to a repository stay in original evidence. */
export function relativePath(value: unknown): string | null {
  const path = text(value)?.replaceAll("\\", "/");
  return path &&
    !path.startsWith("/") &&
    !path.includes("\0") &&
    !/^[A-Za-z]:/.test(path) &&
    !path.split("/").includes("..")
    ? path
    : null;
}

// Hosted findings do not identify the scanner operating system or its path separator.
export function hostedRepositoryPath(value: unknown) {
  const path = text(value);
  return path && !path.includes("\\") && !path.includes("://")
    ? relativePath(path)
    : null;
}

export function stableId(prefix: string, fields: unknown[]): string {
  return `${prefix}:${hash("sha256", JSON.stringify(fields))}`;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
const gunzipAsync = promisify(gunzip);

async function readScannerBytes(path: string): Promise<Buffer> {
  const bytes = await readFile(path);
  return bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipAsync(bytes) : bytes;
}

export async function readScannerText(path: string): Promise<string> {
  return strictUtf8.decode(await readScannerBytes(path));
}

export function parseJsonOrJsonl(contents: string): unknown {
  try {
    return JSON.parse(contents);
  } catch {
    return contents
      .split(/\r?\n/u)
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  }
}

export function decodeScannerJson(bytes: ArrayBuffer | Uint8Array): string {
  try {
    return strictUtf8.decode(bytes);
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner report is not valid UTF-8. ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

/** Canonical decimal digits of a positive int64 JSON number without rounding it. */
export function positiveInt64(source: string): string | undefined {
  const parts = /^(0|[1-9]\d*)(?:\.(\d+))?(?:e([+-]?\d+))?$/iu.exec(source);
  if (!parts) return;
  const fraction = parts[2] ?? "";
  const digits = (parts[1]! + fraction).replace(/^0+/u, "");
  const length = digits.length + Number(parts[3] ?? 0) - fraction.length;
  if (
    !digits ||
    length < 1 ||
    length > 19 ||
    /[1-9]/u.test(digits.slice(length))
  )
    return;
  const id = digits.slice(0, length).padEnd(length, "0");
  if (length < 19 || id <= "9223372036854775807") return id;
}

/** Sparse witness for original JSON numbers encoded as exact text in hosted exports. */
export interface HostedNumericFields {
  [key: string]: string | HostedNumericFields;
}
const numberFields = new WeakMap<object, HostedNumericFields>();

function exactNumber(key: string, value: number, token?: string): boolean {
  return (
    !Number.isFinite(value) ||
    (Number.isInteger(value) &&
      (!Number.isSafeInteger(value) ||
        (key === "id" &&
          value > 0 &&
          token !== undefined &&
          token !== String(value) &&
          !positiveInt64(token))))
  );
}

export function parseHostedScannerJson(source: string): unknown {
  if (!possiblyUnsafeJsonNumber.test(source)) return JSON.parse(source);
  return JSON.parse(
    source,
    function (
      this: object,
      key,
      value: unknown,
      context?: { source?: string },
    ) {
      const token = context?.source;
      const field =
        typeof value === "number" && exactNumber(key, value, token)
          ? requiredText(token, "Exact scanner numeric value")
          : value && typeof value === "object"
            ? numberFields.get(value)
            : undefined;
      if (field !== undefined) {
        const fields: HostedNumericFields =
          numberFields.get(this) ?? Object.create(null);
        fields[key] = field;
        numberFields.set(this, fields);
      }
      return value;
    },
  );
}

/** Semgrep's int64 IDs can also be supplied as text in saved exports. */
export function hostedId(record: Record<string, unknown>): unknown {
  return numberFields.get(record)?.["id"] ?? record["id"];
}

function mapNumbers(data: unknown, fields: unknown, encode: boolean): object {
  if (!data || typeof data !== "object" || !isRecord(fields))
    throw new Error("Invalid scanner numeric fields.");
  const copy = Array.isArray(data) ? [...data] : { ...data };
  const values = copy as Record<string, unknown>;
  const restored = {
    ...numberFields.get(data),
    ...fields,
  } as HostedNumericFields;
  for (const [key, field] of Object.entries(fields)) {
    if (!Object.hasOwn(copy, key))
      throw new Error(
        "Incomplete scanner export: invalid scanner numeric field.",
      );
    if (typeof field === "string") {
      if (
        !encode &&
        (values[key] !== field ||
          !/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:e[+-]?\d+)?$/iu.test(field) ||
          !exactNumber(key, Number(field), field))
      )
        throw new Error("Invalid exact scanner number.");
      values[key] = encode ? field : Number(field);
    } else {
      const child = mapNumbers(values[key], field, encode);
      values[key] = child;
      if (!encode) restored[key] = numberFields.get(child)!;
    }
  }
  if (!encode) numberFields.set(copy, restored);
  return copy;
}

export function hostedWireValue<T>(
  data: T,
  metadata?: HostedNumericFields,
  path: string[] = [],
): T {
  const fields = data && typeof data === "object" && numberFields.get(data);
  if (!fields) return data;
  if (metadata) {
    for (const key of path.slice(0, -1))
      metadata = (metadata[key] ??= Object.create(null)) as HostedNumericFields;
    metadata[path.at(-1)!] = fields;
  }
  return mapNumbers(data, fields, true) as T;
}

export function restoreHostedNumbers(
  report: Record<string, unknown>,
): Record<string, unknown> {
  const fields = report["numericFields"];
  if (fields === undefined) return report;
  if (!isRecord(fields) || Object.hasOwn(fields, "numericFields"))
    throw new Error("Invalid scanner numeric fields.");
  return mapNumbers(report, fields, false) as Record<string, unknown>;
}

// Sixteen mantissa digits may lose precision even if the parsed integer is safe.
// A positive exponent can also overflow. A match inside a string only costs a parse.
const possiblyUnsafeJsonNumber =
  /(?:\[|[:,])\s*-?(?:(?:\d\.?){16}|\d+(?:\.\d+)?e\+?\d)/iu;

export async function readScannerJson(
  path: string,
  hostedFormat?: string,
): Promise<unknown> {
  const decoded = decodeScannerJson(await readScannerBytes(path));
  try {
    const json = decoded.replace(/^\uFEFF/u, "");
    const report: unknown = JSON.parse(json);
    return hostedFormat &&
      isRecord(report) &&
      report["format"] === hostedFormat &&
      possiblyUnsafeJsonNumber.test(json)
      ? parseHostedScannerJson(json)
      : report;
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner JSON could not be parsed. ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

/** Empty reference containers and property-bag metadata do not externalize data. */
export function hasSarifExternalPropertyReferences(value: unknown): boolean {
  if (value == null) return false;
  return Object.entries(
    record(value, "SARIF external property references"),
  ).some(
    ([key, references]) =>
      key !== "properties" &&
      (!Array.isArray(references) || references.length > 0),
  );
}

const sarifArtifactLocationFields = new Set([
  "artifactLocation",
  "analysisTarget",
  "executableLocation",
  "workingDirectory",
  "stdin",
  "stdout",
  "stderr",
  "stdoutStderr",
  "mappedTo",
  "displayBase",
]);

/** Keep original artifact indexes; omit only inventory unrelated to this finding. */
export function sarifRunContextForResult(
  runContext: Record<string, unknown>,
  ...selectedEvidence: unknown[]
): Record<string, unknown> {
  const { artifacts, ...context } = runContext;
  if (!Array.isArray(artifacts) || artifacts.length === 0) return runContext;
  const locations: Record<string, unknown>[] = [];
  let hasArtifactLink = false;
  function visit(value: unknown): void {
    if (typeof value === "string") {
      // SARIF message links can refer to an artifact without an artifactLocation.
      if (/sarif:/iu.test(value)) hasArtifactLink = true;
    } else if (Array.isArray(value)) value.forEach(visit);
    else if (isRecord(value))
      for (const [key, child] of Object.entries(value)) {
        if (key === "properties") continue;
        if (sarifArtifactLocationFields.has(key) && isRecord(child))
          locations.push(child);
        if (
          ["locations", "responseFiles", "analysisToolLogFiles"].includes(
            key,
          ) &&
          Array.isArray(child)
        )
          locations.push(...child.filter(isRecord));
        if (key === "originalUriBaseIds" && isRecord(child))
          locations.push(...Object.values(child).filter(isRecord));
        visit(child);
      }
  }
  visit([context, ...selectedEvidence]);
  if (hasArtifactLink) return runContext;
  const unresolvedUri = /[%:\\]|(?:^|\/)\.\.?(?:\/|$)/u;
  for (const location of locations) {
    if (typeof location["index"] === "number" && location["index"] >= 0)
      return runContext;
    if (typeof location["uri"] !== "string") continue;
    for (const artifact of artifacts) {
      if (!isRecord(artifact) || !isRecord(artifact["location"])) continue;
      const candidate = artifact["location"];
      // Keep URI spellings that need resolution; evidence is never rewritten.
      if (
        location["uriBaseId"] !== candidate["uriBaseId"] ||
        unresolvedUri.test(location["uri"]) ||
        (typeof candidate["uri"] === "string" &&
          unresolvedUri.test(candidate["uri"])) ||
        location["uri"] === candidate["uri"]
      )
        return runContext;
    }
  }
  return context;
}

/** Duplicate IDs cannot identify a single rule in this run. */
export function indexSarifRules(rules: Record<string, unknown>[]) {
  const byId = new Map<
    unknown,
    { rule: Record<string, unknown>; index: number } | null
  >();
  rules.forEach((rule, index) => {
    const id = rule["id"];
    byId.set(id, byId.has(id) ? null : { rule, index });
  });
  return byId;
}

/** Exclude every colliding record: choosing the first could overwrite another occurrence. */
export function normalizeRecords<T>(
  records: T[],
  projectEvidence: (record: T, id: string) => ExternalFinding["evidence"],
  identify: (record: T) => string,
  target: "local" | "cloud" = "cloud",
): ExternalFindings {
  const result: ExternalFindings = {
    read: records.length,
    findings: [],
    excluded: [],
  };
  const identified: { position: number; value: T; id: string }[] = [];
  const counts = new Map<string, number>();
  for (const [index, value] of records.entries()) {
    try {
      const id = identify(value);
      if (
        !id.trim() ||
        id.includes("\0") ||
        (target === "cloud" && Buffer.byteLength(id) > 512)
      )
        throw new Error(
          target === "cloud"
            ? "Source finding ID must contain 1–512 UTF-8 bytes and no NUL characters."
            : "Source finding ID must be nonempty and contain no NUL characters.",
        );
      identified.push({ position: index + 1, value, id });
      counts.set(id, (counts.get(id) ?? 0) + 1);
    } catch (error) {
      result.excluded.push({
        position: index + 1,
        source_finding_id: null,
        reason: errorMessage(error),
      });
    }
  }
  for (const { position, value, id } of identified) {
    if (counts.get(id)! > 1) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason:
          "Ambiguous duplicate source identity; select one complete finding or separate source projects.",
      });
      continue;
    }
    try {
      result.findings.push({
        source_finding_id: id,
        evidence: projectEvidence(value, id),
      });
    } catch (error) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason: errorMessage(error),
      });
    }
  }
  result.excluded.sort((a, b) => a.position - b.position);
  return result;
}
