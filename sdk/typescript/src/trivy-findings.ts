import { posix, sep } from "node:path";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  isGitHubCloudHost,
  normalizeGitRepositoryUrl,
  parseGitRemote,
} from "./git-remote.js";
import { isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

type NativeRecord = Record<string, unknown>;

const urlScheme = /^[a-z][a-z\d+.-]*:\/\//iu;
const javaArchiveAncestor = /\.(?:jar|war|ear|par)\//iu;

const sshProtocols = new Set(["ssh:", "git+ssh:", "ssh+git:"]);

function networkRepository(value: unknown): string | null {
  const source = text(value);
  if (!source || /^(?:[a-z]:|[./\\])/iu.test(source)) return null;
  const remote = parseGitRemote(source);
  if (!remote) return null;
  const { url } = remote;
  const ssh = sshProtocols.has(url.protocol);
  if (url.password || (!ssh && url.username) || /[?#\t\r\n]/u.test(source))
    throw new Error(
      "Use a Trivy repository URL without credentials, a query, or a fragment.",
    );
  if (url.protocol === "file:") return null;
  if (
    !url.hostname ||
    !remote.path ||
    (!ssh &&
      !["http:", "https:", "git:", "ftp:", "ftps:"].includes(url.protocol))
  )
    throw new Error("Unsupported Trivy repository URL.");
  return source;
}

function comparableGitHubRemote(
  remote: string,
  cloudRepositoryUrl?: string,
): string | undefined {
  if (/[?#\t\r\n]/u.test(remote)) return undefined;
  const parsed = parseGitRemote(remote);
  if (!parsed) return undefined;
  const prefix = `${parsed.url.protocol}//`;
  // Git dispatches mixed-case schemes to distinct remote helpers.
  if (!parsed.scpStyle && !remote.startsWith(prefix)) return undefined;
  const host = parsed.url.hostname.toLowerCase();
  const githubUrl =
    cloudRepositoryUrl ??
    (isGitHubCloudHost(host) ? `https://${host}` : undefined);
  if (!parsed.scpStyle && sshProtocols.has(parsed.url.protocol)) {
    const authorityStart = prefix.length;
    const pathStart = remote.indexOf("/", authorityStart);
    if (pathStart < 0 || remote.slice(pathStart) !== parsed.url.pathname)
      return undefined;
    remote = `ssh://${remote.slice(authorityStart)}`;
  }
  const normalized = normalizeGitRepositoryUrl(remote, githubUrl);
  if (!/^https?:\/\//iu.test(normalized)) return undefined;
  if (
    !isGitHubCloudHost(new URL(normalized).hostname) &&
    (!cloudRepositoryUrl || new URL(cloudRepositoryUrl).hostname !== host)
  )
    return undefined;
  return normalized;
}

export function trivyRemoteKey(
  remote: string,
  cloudRepositoryUrl?: string,
  checkout = false,
): string {
  const normalized = comparableGitHubRemote(remote, cloudRepositoryUrl);
  if (!normalized) return remote;
  // GitHub identifies an HTTPS repository by host and path. Other Git servers
  // may use the HTTP username to select the repository.
  const url = checkout
    ? normalized.replace(/^(https?:\/\/)[^/\\?#]*@/iu, "$1")
    : normalized;
  return cloudRepositoryUrl
    ? cloudRepositoryUrlKey(url)
    : repositoryUrlKey(url);
}

const sshScheme = /^(?:ssh|git\+ssh|ssh\+git):\/\//u;

function userlessSsh(url: string): boolean {
  return sshScheme.test(url) && !new URL(url).username;
}

function requireTrivySshUsers(urls: readonly string[]): void {
  if (urls.some(userlessSsh))
    throw new Error(
      "Trivy omitted the SSH user, so this report cannot identify its source repository. Verify the checkout uses the intended git@host:path or HTTPS remote and regenerate the report.",
    );
}

/** Findings are stored and published individually, without the batch repository URLs. */
export function validateNormalizedTrivySources(input: ExternalFindings): void {
  for (const url of input.sourceRepositoryUrls ?? []) networkRepository(url);
  requireTrivySshUsers(input.sourceRepositoryUrls ?? []);
  for (const { evidence } of input.findings) {
    const report = evidence.source_data?.["report"];
    if (isRecord(report) && report["SchemaVersion"] === 2) {
      const name = text(report["ArtifactName"]);
      if (name && urlScheme.test(name)) networkRepository(name);
    }
    const { urls } = trivyReportRemotes(report);
    requireTrivySshUsers(urls);
    if (
      input.sourceRepositoryUrls?.length &&
      !evidence.details?.repository?.url &&
      !urls.length
    )
      throw new Error(
        "For a repository-bound Trivy report, retain the source repository in each finding's source_data.report or details.repository.url.",
      );
  }
}

export function trivyReportRemotes(report: unknown) {
  if (!isRecord(report) || report["SchemaVersion"] !== 2)
    return { urls: [], artifactRepository: undefined };
  const metadata = report["Metadata"];
  const repository = networkRepository(
    isRecord(metadata) && metadata["RepoURL"],
  );
  // Only an explicitly identified filesystem artifact uses its name as a display label.
  const name =
    report["ArtifactType"] !== "filesystem" && text(report["ArtifactName"]);
  let artifact: string | null = null;
  if (name && urlScheme.test(name)) {
    artifact = networkRepository(name);
  } else if (
    name &&
    /^[^./:\\][^/:\\]*\//u.test(name) &&
    repository === `https://${name}`
  ) {
    // Trivy can omit the HTTPS scheme, but also accepts relative checkout paths.
    artifact = repository;
  }
  const artifactRepository =
    artifact && artifact !== repository ? artifact : undefined;
  if (artifactRepository && report["ArtifactType"] === "repository") {
    // Trivy parses HTTP target arguments as URLs. The checkout uses Git's literal transport.
    const target = artifactRepository.replace(/^https?:/iu, (scheme) =>
      scheme.toLowerCase(),
    );
    if (target !== artifactRepository && (!repository || target === repository))
      return { urls: [target], artifactRepository };
  }
  const urls = [repository, artifact].filter((url) => url !== null);
  const weak = urls.find(userlessSsh);
  if (weak && urls.length === 2) {
    const declared = urls.find((url) => url !== weak);
    if (!declared) return { urls: [weak], artifactRepository };
    // Compare the lost user against another retained declaration, never the destination.
    if (
      weak === declared.replace(/:\/\/[^/@]+@/u, "://") ||
      declared === weak.replace(sshScheme, "https://")
    )
      return { urls: [declared, declared], artifactRepository };
  }
  return { urls, artifactRepository };
}

export function requireMatchingTrivyRemotes(
  urls: readonly string[],
  githubUrl?: string,
): void {
  if (
    urls.length > 1 &&
    new Set(urls.map((url) => trivyRemoteKey(url, githubUrl))).size > 1
  )
    throw new Error("Trivy source URLs identify different repositories.");
}

/** Compare the report's claims using the authenticated host when available. */
export function trivyRepositoryUrl(
  report: unknown,
  cloudRepositoryUrl?: string,
): string | null {
  const { urls } = trivyReportRemotes(report);
  requireMatchingTrivyRemotes(urls, cloudRepositoryUrl);
  const remote = urls[0];
  return remote && cloudRepositoryUrl
    ? (comparableGitHubRemote(remote, cloudRepositoryUrl) ?? remote)
    : (remote ?? null);
}

function repositoryPath(value: unknown, directory = false): string | null {
  const raw = text(value);
  if (!raw || !relativePath(raw)) return null;
  // Check the emitted spelling across platforms while retaining literal POSIX backslashes.
  const path = posix.normalize(raw);
  const portable = posix.normalize(path.replaceAll("\\", "/"));
  const firstComponent = portable.split("/", 1)[0]!;
  const at = firstComponent.indexOf("@", 1);
  const scpStyle = at !== -1 && firstComponent.indexOf(":", at + 2) !== -1;
  return relativePath(portable) &&
    (directory || (portable !== "." && !portable.endsWith("/"))) &&
    !scpStyle &&
    !/^[a-z][a-z\d+.-]*:\//iu.test(portable)
    ? path
    : null;
}

const aggregateTargets = new Map([
  ["python-pkg", "Python"],
  ["conda-pkg", "Conda"],
  ["gemspec", "Ruby"],
  ["node-pkg", "Node.js"],
  ["jar", "Java"],
  ["kubernetes", "Kubernetes"],
]);
const nonManifestTypes = new Set([
  "gobinary",
  "rustbinary",
  "jar",
  "javascript",
]);

function resolveScanRoot(
  scanRoot: string | undefined,
  remoteRepository: boolean,
): string {
  if (scanRoot === undefined) {
    if (remoteRepository) return ".";
    throw new Error(
      "Specify --trivy-scan-root relative to the repository; use . for a whole-checkout scan.",
    );
  }
  const root = repositoryPath(scanRoot.split(sep).join("/"), true)?.replace(
    /\/$/u,
    "",
  );
  if (!root)
    throw new Error(
      "--trivy-scan-root must be a repository-relative directory without traversal.",
    );
  if (remoteRepository && root !== ".")
    throw new Error(
      "A remote Trivy repository scan starts at the checkout root; --trivy-scan-root must be .",
    );
  return root;
}

function scopedPath(root: string, value: unknown): string | null {
  const path = repositoryPath(value);
  return path === null ? null : posix.join(root, path);
}

function pick(source: NativeRecord, fields: string[]): NativeRecord {
  return Object.fromEntries(
    fields
      .filter((field) => Object.hasOwn(source, field))
      .map((field) => [field, source[field]]),
  );
}

function packageKeys(
  id: unknown,
  identifier: unknown,
  name: unknown,
  version: unknown,
  path: unknown,
) {
  const file = repositoryPath(path) ?? text(path);
  const key = (kind: string, value: unknown) =>
    text(value) && JSON.stringify([kind, value, file]);
  const native = isRecord(identifier) ? identifier : {};
  return {
    id: key("id", id),
    uid: key("uid", native["UID"]),
    purl: key("purl", native["PURL"]),
    bomRef: key("bomRef", native["BOMRef"]),
    nameVersion:
      text(name) &&
      text(version) &&
      JSON.stringify(["name-version", name, version, file]),
  };
}

type PackageIndex = Map<
  string,
  { pkg: NativeRecord; keys: ReturnType<typeof packageKeys> } | null
>;

function indexPackages(packages: unknown): PackageIndex {
  const index: PackageIndex = new Map();
  for (const value of array(packages ?? [], "Trivy Packages")) {
    const pkg = record(value, "Trivy package");
    const keys = packageKeys(
      pkg["ID"],
      pkg["Identifier"],
      pkg["Name"],
      pkg["Version"],
      pkg["FilePath"],
    );
    const match = { pkg, keys };
    for (const key of Object.values(keys))
      if (key) index.set(key, index.has(key) ? null : match);
  }
  return index;
}

function matchingPackage(vulnerability: NativeRecord, index: PackageIndex) {
  const keys = packageKeys(
    vulnerability["PkgID"],
    vulnerability["PkgIdentifier"],
    vulnerability["PkgName"],
    vulnerability["InstalledVersion"],
    vulnerability["PkgPath"],
  );
  const supplied = (["uid", "id", "purl", "bomRef"] as const).filter(
    (field) => keys[field],
  );
  for (const field of supplied.length ? supplied : (["nameVersion"] as const)) {
    const key = keys[field];
    const match = key && index.get(key);
    if (
      match &&
      agreesWhenPresent(vulnerability["PkgName"], match.pkg["Name"]) &&
      agreesWhenPresent(
        vulnerability["InstalledVersion"],
        match.pkg["Version"],
      ) &&
      supplied.every((id) => !match.keys[id] || keys[id] === match.keys[id])
    )
      return match.pkg;
  }
  return null;
}

function agreesWhenPresent(detected: unknown, inventoried: unknown): boolean {
  return !text(detected) || !text(inventoried) || detected === inventoried;
}

interface Entry {
  result: { Target?: string; Type: string; Class: string };
  packages: PackageIndex;
  value: unknown;
}

function occurrence(entry: Entry | string, root: string) {
  if (typeof entry === "string") throw new Error(entry);
  const vulnerability = record(entry.value, "Trivy vulnerability");
  const { Target, Type } = entry.result;
  return {
    ...entry,
    vulnerability,
    advisory: requiredText(
      vulnerability["VulnerabilityID"],
      "Trivy VulnerabilityID",
    ),
    name: requiredText(vulnerability["PkgName"], "Trivy PkgName"),
    pkgPath: text(vulnerability["PkgPath"]),
    targetPath:
      aggregateTargets.get(Type) === Target ? null : scopedPath(root, Target),
    packagePath: scopedPath(root, vulnerability["PkgPath"]),
  };
}

/** Import native Trivy dependency occurrences. Local scans require their checkout-relative
 * scan root. The package ecosystem is the PURL type when supplied, otherwise the analyzer. */
export function normalizeTrivyFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
  scanRoot?: string,
): ExternalFindings {
  const document = record(input, "Trivy report");
  if (document["SchemaVersion"] !== 2)
    throw new Error(
      "Expected a native Trivy JSON report with SchemaVersion 2.",
    );
  if (
    document["ArtifactType"] !== "repository" &&
    document["ArtifactType"] !== "filesystem"
  )
    throw new Error(
      "Only Trivy repository and filesystem reports are supported.",
    );
  const metadata = record(document["Metadata"] ?? {}, "Trivy Metadata");
  const { urls, artifactRepository } = trivyReportRemotes(document);
  const report = {
    ...pick(document, [
      "SchemaVersion",
      "ArtifactType",
      "ArtifactID",
      "ReportID",
      "CreatedAt",
    ]),
    ...(isRecord(document["Trivy"])
      ? { Trivy: pick(document["Trivy"], ["Version"]) }
      : {}),
    ...(artifactRepository ? { ArtifactName: artifactRepository } : {}),
    Metadata: pick(metadata, ["RepoURL", "Branch", "Commit"]),
  };
  const [repository, artifact] = urls;
  if (repository && artifact && repository !== artifact) {
    // The destination verifies these possible Enterprise aliases before import.
    const { url } = parseGitRemote(repository)!;
    const githubTransport =
      ["http:", "https:"].includes(url.protocol) ||
      sshProtocols.has(url.protocol);
    requireMatchingTrivyRemotes(
      urls,
      githubTransport ? `https://${url.hostname}` : undefined,
    );
  }
  const root = resolveScanRoot(scanRoot, urls.length === 2);

  const entries: (Entry | string)[] = [];
  for (const group of array(document["Results"] ?? [], "Trivy Results")) {
    const result = record(group, "Trivy result");
    if (result["Class"] !== "lang-pkgs") {
      entries.push(
        `Unsupported Trivy result class: ${text(result["Class"]) ?? "(missing)"}. Only lang-pkgs vulnerabilities are imported.`,
      );
      continue;
    }
    for (const field of [
      "Misconfigurations",
      "Secrets",
      "Licenses",
      "CryptoAssets",
      "CustomResources",
      "ExperimentalModifiedFindings",
    ])
      if (array(result[field] ?? [], `Trivy ${field}`).length)
        entries.push(`Unsupported Trivy ${field} in lang-pkgs result.`);

    const vulnerabilities = array(
      result["Vulnerabilities"] ?? [],
      "Trivy Vulnerabilities",
    );
    if (!vulnerabilities.length) continue;
    const reportedTarget = result["Target"];
    if (reportedTarget != null && typeof reportedTarget !== "string")
      throw new Error("Trivy result Target must be text.");
    const context = {
      ...(reportedTarget == null ? {} : { Target: reportedTarget }),
      Type: requiredText(result["Type"], "Trivy result Type"),
      Class: result["Class"],
    };
    const packages = indexPackages(result["Packages"]);
    for (const value of vulnerabilities)
      entries.push({ result: context, packages, value });
  }

  const findings = normalizeRecords(
    entries,
    (entry, id) => {
      const {
        result,
        packages,
        vulnerability,
        advisory,
        name,
        targetPath,
        pkgPath,
        packagePath,
      } = occurrence(entry, root);
      const identifier = vulnerability["PkgIdentifier"];
      const purl = isRecord(identifier) ? text(identifier["PURL"]) : null;
      const ecosystem =
        purl?.match(/^pkg:([a-z][a-z\d.+-]*)\//iu)?.[1]?.toLowerCase() ??
        result.Type;
      const pkg = matchingPackage(vulnerability, packages);
      const manifest = nonManifestTypes.has(result.Type) ? null : targetPath;
      const starts = new Set<number>();
      if (manifest && pkg)
        for (const range of array(
          pkg["Locations"] ?? [],
          "Trivy package Locations",
        )) {
          const start = isRecord(range) && range["StartLine"];
          if (
            typeof start === "number" &&
            Number.isSafeInteger(start) &&
            start > 0
          )
            starts.add(start);
        }
      const locations: { path: string; line: number | null }[] = [];
      if (targetPath) {
        if (starts.size === 0) locations.push({ path: targetPath, line: null });
        for (const line of starts) locations.push({ path: targetPath, line });
      }
      // Trivy uses the same spelling for archive members and files in exploded archives.
      const ambiguousJavaPath =
        result.Type === "jar" && javaArchiveAncestor.test(pkgPath ?? "");
      if (packagePath && packagePath !== targetPath && !ambiguousJavaPath)
        locations.push({ path: packagePath, line: null });
      const severity = text(vulnerability["Severity"])?.toLowerCase();
      return {
        source_finding_id: id,
        evidence: validateExternalEvidence(
          {
            title: text(vulnerability["Title"]) ?? `${advisory} in ${name}`,
            severity:
              severity &&
              ["critical", "high", "medium", "low"].includes(severity)
                ? severity
                : "unknown",
            description: text(vulnerability["Description"]),
            url: text(vulnerability["PrimaryURL"]),
            advisory_ids: [
              ...new Set([advisory, ...strings(vulnerability["VendorIDs"])]),
            ],
            packages: [
              {
                name,
                ecosystem,
                manifest_path: manifest,
                installed_version: text(vulnerability["InstalledVersion"]),
                fixed_versions:
                  text(vulnerability["FixedVersion"])
                    ?.split(",")
                    .map((version) => version.trim())
                    .filter(Boolean) ?? [],
              },
            ],
            locations,
            branch: text(metadata["Branch"]),
            source_scan_id: text(document["ReportID"]),
            source_data: structuredClone({
              scanRoot: root,
              report,
              result,
              vulnerability,
              ...(pkg
                ? {
                    package: pick(pkg, [
                      "ID",
                      "Name",
                      "Version",
                      "Identifier",
                      "FilePath",
                      "Relationship",
                      "Locations",
                    ]),
                  }
                : {}),
            }),
          },
          target,
        ),
      };
    },
    (entry) => {
      const { result, advisory, name, pkgPath, targetPath, packagePath } =
        occurrence(entry, root);
      const manifest = targetPath ?? text(result.Target);
      const concretePath = packagePath ?? pkgPath;
      return stableId("trivy", [
        result.Type,
        manifest,
        advisory,
        name,
        concretePath === manifest ? null : concretePath,
        ...(!targetPath && !packagePath && root !== "." ? [root] : []),
      ]);
    },
    target,
  );
  if (urls.length) findings.sourceRepositoryUrls = [...new Set(urls)];
  return findings;
}

export async function readTrivyFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
  scanRoot?: string,
): Promise<ExternalFindings> {
  return normalizeTrivyFindings(await readScannerJson(path), target, scanRoot);
}
