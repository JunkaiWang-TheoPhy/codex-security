import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { ExternalImportTarget } from "../src/external-import-contract.js";
import {
  inspectorReportRepositories,
  normalizeInspectorFindings,
  readInspectorFindings,
} from "../src/inspector-findings.js";
import {
  inspectorIntegrationArn,
  inspectorPackageFinding,
  inspectorProjectId,
  inspectorReport,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

function normalize(
  findings: unknown[],
  source = inspectorRepositoryUrl,
  target: ExternalImportTarget = "cloud",
  projectMap?: ReadonlyMap<string, string>,
) {
  return normalizeInspectorFindings({ findings }, source, target, projectMap);
}

function codeFinding(
  filePath = "src/example.ts",
  fileName = "example.ts",
  startLine = 8,
) {
  const { packageVulnerabilityDetails: _packages, ...common } =
    inspectorPackageFinding();
  return {
    ...common,
    type: "CODE_VULNERABILITY",
    findingArn: common.findingArn.replace(/a{32}$/u, "b".repeat(32)),
    title: "Synthetic code finding",
    codeVulnerabilityDetails: {
      detectorId: "synthetic-detector",
      detectorName: "Synthetic detector",
      cwes: ["CWE-79"],
      detectorTags: ["example-tag"],
      filePath: { fileName, filePath, startLine, endLine: 12 },
    },
  };
}

function projectFinding(
  repoChanges: Record<string, unknown>,
  resourceChanges: Record<string, unknown> = {},
) {
  const finding = inspectorPackageFinding();
  const resource = finding.resources[0]!;
  Object.assign(resource.details.codeRepository, repoChanges);
  Object.assign(resource, resourceChanges);
  return finding;
}

test("projects the vulnerable package and advisory IDs without attributing the advisory to the scanned repository", () => {
  const report = inspectorReport();
  const native = report.findings[0]!;
  const original = structuredClone(native);
  const output = normalizeInspectorFindings(report, inspectorRepositoryUrl);
  expect(output.read).toBe(1);
  expect(output.excluded).toEqual([]);
  const row = output.findings[0]!;
  expect(row.source_finding_id).toBe(native.findingArn);
  expect(row.evidence).toMatchObject({
    title: native.title,
    severity: "high",
    description: native.description,
    advisory_ids: ["CVE-2099-1234", "GHSA-2345-6789-cfgh"],
    url: native.packageVulnerabilityDetails.sourceUrl,
    packages: [
      {
        name: "example-package",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
        ecosystem: "npm",
        manifest_path: "apps/web/package-lock.json",
      },
    ],
    locations: [{ path: "apps/web/package-lock.json", line: null }],
    source_updated_at: Date.parse(native.updatedAt) / 1000,
    source_data: {
      sourceRepositoryUrl: inspectorRepositoryUrl,
      finding: original,
    },
  });
  expect(row.evidence).not.toHaveProperty("details");
  expect(
    normalize([native], inspectorRepositoryUrl, "local").findings[0]!.evidence,
  ).not.toHaveProperty("details");
  expect(row.evidence.source_data?.["finding"]).toMatchObject({
    status: "ACTIVE",
    packageVulnerabilityDetails: { source: "NVD" },
  });
  expect(row.evidence.branch ?? null).toBeNull();
  expect(row.evidence.code_revision ?? null).toBeNull();
  expect(row.evidence.source_scan_id ?? null).toBeNull();
  expect(row).not.toHaveProperty("assessment");
  expect(native).toEqual(original);
  native.status = "CLOSED";
  native.packageVulnerabilityDetails.vulnerablePackages[0]!.version = "^2.0";
  const updated = normalize([native]).findings[0]!;
  expect(updated.source_finding_id).toBe(row.source_finding_id);
  expect(updated.evidence).not.toHaveProperty("details");
  expect(updated.evidence.packages![0]!.installed_version ?? null).toBeNull();
  expect(row.evidence.source_data?.["finding"]).toEqual(original);
  expect(updated.evidence.source_data?.["finding"]).toMatchObject({
    status: "CLOSED",
  });
});

test("code detector tags, ranges and weaknesses stay native; only supplied repository locations are projected", () => {
  const code = codeFinding();
  const output = normalize([code]);
  const evidence = output.findings[0]!.evidence;
  expect(evidence.locations).toEqual([{ path: "src/example.ts", line: 8 }]);
  expect(evidence.details ?? null).toBeNull();
  expect(evidence.source_data?.["finding"]).toEqual(code);
  for (const file of [
    "/tmp/example.ts",
    "C:\\work\\example.ts",
    "src/../example.ts",
    "file:///tmp/example.ts",
    "https://example.invalid/example.ts",
    "~/example.ts",
    "./C:/work/example.ts",
  ])
    expect(
      normalize([codeFinding(file)]).findings[0]!.evidence.locations,
    ).toEqual([]);
  expect(
    normalize([codeFinding("src/", "example.ts")]).findings[0]!.evidence
      .locations,
  ).toEqual([]);
  expect(
    normalize([codeFinding("src/example.ts", "different.ts")]).findings[0]!
      .evidence.locations,
  ).toEqual([]);
  expect(
    normalize([codeFinding("src\\example.ts", "example.ts", 0)]).findings[0]!
      .evidence.locations,
  ).toEqual([{ path: "src/example.ts", line: null }]);
});

test("no fix version, package path or scan time is inferred from other fields", () => {
  const native = inspectorPackageFinding();
  const pkg = { name: "synthetic", version: "^1", filePath: "/image/example" };
  const evidence = normalize([
    {
      ...native,
      updatedAt: undefined,
      severity: "UNTRIAGED",
      packageVulnerabilityDetails: {
        ...native.packageVulnerabilityDetails,
        vulnerablePackages: [pkg],
      },
    },
  ]).findings[0]!.evidence;
  expect(evidence.locations).toEqual([]);
  expect(evidence.severity).toBe("unknown");
  expect(evidence.packages![0]).toMatchObject({
    name: "synthetic",
    installed_version: null,
    manifest_path: null,
    ecosystem: null,
    fixed_versions: [],
  });
  expect(evidence.source_updated_at ?? null).toBeNull();
});

test("distinguishes native package file locations from dependency manifests and version selectors", () => {
  const native = inspectorPackageFinding();
  const base = native.packageVulnerabilityDetails.vulnerablePackages[0]!;
  const values = [
    {
      ...base,
      filePath: "src/example.ts",
      packageManager: "UNKNOWN",
      version: "1.2.x",
      fixedInVersion: ">=2.0",
    },
    {
      ...base,
      filePath: "api/requirements-dev.txt",
      packageManager: "PIP",
      version: "1!2.3rc1+lab",
    },
    { ...base, filePath: "../package-lock.json", version: "workspace:*" },
  ];
  const evidence = normalize([
    {
      ...native,
      packageVulnerabilityDetails: {
        ...native.packageVulnerabilityDetails,
        vulnerablePackages: values,
      },
    },
  ]).findings[0]!.evidence;
  expect(evidence.packages).toMatchObject([
    {
      installed_version: null,
      fixed_versions: [],
      ecosystem: null,
      manifest_path: null,
    },
    {
      installed_version: "1!2.3rc1+lab",
      ecosystem: "pypi",
      manifest_path: "api/requirements-dev.txt",
    },
    { installed_version: null, manifest_path: null },
  ]);
  expect(evidence.locations).toEqual([
    { path: "src/example.ts", line: null },
    { path: "api/requirements-dev.txt", line: null },
  ]);
  expect(evidence.source_data?.["finding"]).toMatchObject({
    packageVulnerabilityDetails: { vulnerablePackages: values },
  });
});

test("projects exact package versions using the reported package ecosystem", () => {
  const finding = inspectorPackageFinding();
  const item = finding.packageVulnerabilityDetails.vulnerablePackages[0]!;
  const pkg = (
    packageManager: string,
    version: string,
    fixedInVersion: string,
  ) => ({ ...item, packageManager, version, fixedInVersion });
  finding.packageVulnerabilityDetails.vulnerablePackages = [
    pkg("YARN", "workspace:1.2.3", "1.2.3-rc.x.1"),
    pkg("NPM", "1.2.3+build.x.1", "2.x"),
    pkg("JAR", "1.+", "1.3"),
    pkg("POM", "First.RELEASE", "Next.RELEASE"),
    pkg("POM", "LATEST", "RELEASE"),
    pkg("JAR", "latest.integration", "[1.3,2.0)"),
    pkg("PYTHONPKG", "1.0+linux.x.1", "1.1+linux.x.1"),
    pkg("OS", "1:2.3-4", "1:2.3-5"),
  ];
  expect(normalize([finding]).findings[0]!.evidence.packages).toMatchObject([
    { installed_version: null, fixed_versions: ["1.2.3-rc.x.1"] },
    { installed_version: "1.2.3+build.x.1", fixed_versions: [] },
    { installed_version: null, fixed_versions: ["1.3"] },
    {
      installed_version: "First.RELEASE",
      fixed_versions: ["Next.RELEASE"],
    },
    { installed_version: null, fixed_versions: [] },
    { installed_version: null, fixed_versions: [] },
    { installed_version: "1.0+linux.x.1", fixed_versions: ["1.1+linux.x.1"] },
    { installed_version: "1:2.3-4", fixed_versions: ["1:2.3-5"] },
  ]);
});

test("accepts both native CLI Unix and ISO timestamps without losing their original representation", () => {
  const native = inspectorPackageFinding();
  const epoch = Date.parse(native.updatedAt) / 1000;
  for (const updatedAt of [
    epoch + 0.125,
    native.updatedAt,
    "2026-01-04T06:06:07.125+01:00",
  ]) {
    const row = normalize([
      {
        ...native,
        firstObservedAt: epoch - 2,
        lastObservedAt: epoch - 1,
        updatedAt,
      },
    ]).findings[0]!;
    expect(row.evidence.source_updated_at).toBe(epoch);
    expect(row.evidence.source_data?.["finding"]).toMatchObject({ updatedAt });
  }
  for (const updatedAt of [
    "January 4",
    "2026-01-04T05:06:07",
    String(epoch),
    null,
  ]) {
    const result = normalize([{ ...native, updatedAt }]);
    expect(result.findings).toHaveLength(0);
    expect(result.excluded[0]?.reason).toContain("timestamp");
  }
});

test("accepts an explicitly empty report but not errors, projections, event envelopes or partial pages", () => {
  expect(normalize([])).toEqual({ read: 0, findings: [], excluded: [] });
  for (const invalid of [
    null,
    [],
    {},
    { Findings: [] },
    { findings: null },
    { findings: [], Error: { Code: "AccessDenied" } },
    { errors: [] },
    { detail: inspectorReport() },
    inspectorPackageFinding(),
  ])
    expect(() =>
      normalizeInspectorFindings(invalid, inspectorRepositoryUrl),
    ).toThrow();
  for (const key of ["nextToken", "NextToken"])
    for (const token of ["synthetic-token", null, ""])
      expect(() =>
        normalizeInspectorFindings(
          { ...inspectorReport(), [key]: token },
          inspectorRepositoryUrl,
        ),
      ).toThrow("continuation");
});

test("counts exclusions and rejects all duplicate finding ARNs without contaminating supported rows", () => {
  const supported = inspectorPackageFinding();
  const duplicate = codeFinding();
  const output = normalize([
    supported,
    null,
    duplicate,
    { ...duplicate, status: "SUPPRESSED" },
  ]);
  expect(output.read).toBe(4);
  expect(output.findings.map((row) => row.source_finding_id)).toEqual([
    supported.findingArn,
  ]);
  expect(
    output.excluded.map(({ position, source_finding_id }) => [
      position,
      source_finding_id,
    ]),
  ).toEqual([
    [2, null],
    [3, duplicate.findingArn],
    [4, duplicate.findingArn],
  ]);
  expect(output.excluded[1]!.reason).toContain("duplicate");
});

test.each([
  "AWS_EC2_INSTANCE",
  "AWS_ECR_CONTAINER_IMAGE",
  "AWS_ECR_REPOSITORY",
  "AWS_LAMBDA_FUNCTION",
])(
  "does not import %s, even when a finding also lists a code repository",
  (type) => {
    const supported = inspectorPackageFinding();
    const other = {
      type,
      id: "opaque-workload",
      tags: { unrelated: "synthetic-workload-only" },
    };
    for (const resources of [[other], [other, ...supported.resources]]) {
      const output = normalize([supported, { ...codeFinding(), resources }]);
      expect(output.read).toBe(2);
      expect(output.findings).toHaveLength(1);
      expect(output.excluded[0]!.position).toBe(2);
      expect(JSON.stringify(output.findings)).not.toContain(
        "synthetic-workload-only",
      );
    }
  },
);

test("rejects network, cross-family and layer payloads on apparently repository-only findings", () => {
  const pkg = inspectorPackageFinding();
  const code = codeFinding();
  const resource = pkg.resources[0]!;
  for (const row of [
    { ...pkg, type: "NETWORK_REACHABILITY" },
    { ...pkg, networkReachabilityDetails: {} },
    { ...code, packageVulnerabilityDetails: pkg.packageVulnerabilityDetails },
    {
      ...pkg,
      resources: [
        {
          ...resource,
          details: { ...resource.details, awsLambdaFunction: {} },
        },
      ],
    },
    {
      ...code,
      codeVulnerabilityDetails: {
        ...code.codeVulnerabilityDetails,
        sourceLambdaLayerArn: "synthetic-layer",
      },
    },
    ...["sourceLayerHash", "sourceLambdaLayerArn"].map((field) => ({
      ...pkg,
      packageVulnerabilityDetails: {
        ...pkg.packageVulnerabilityDetails,
        vulnerablePackages: [
          {
            ...pkg.packageVulnerabilityDetails.vulnerablePackages[0],
            [field]: "synthetic-layer",
          },
        ],
      },
    })),
  ]) {
    const output = normalize([row]);
    expect(output.findings).toEqual([]);
    expect(output.excluded).toHaveLength(1);
    expect(output.excluded[0]!.source_finding_id).toBe(row.findingArn);
  }
});

test("requires a complete explicit mapping; a bare name or opaque project ID cannot assign a host or namespace", () => {
  for (const source of [
    "",
    "example/project",
    "https://example.invalid/project",
    "https://u:p@example.invalid/org/project",
    inspectorRepositoryUrl + "?",
    inspectorRepositoryUrl + "#ref",
    "https://example.invalid/other/../example/project",
    "https://example.invalid/example%2fgroup/project",
  ])
    expect(() => normalize([], source)).toThrow();
  for (const name of [
    undefined,
    "project",
    inspectorProjectId,
    "other/project",
    "https://git.example.test/example/project",
  ])
    expect(() => normalize([projectFinding({ projectName: name })])).toThrow();
  expect(() =>
    normalize([
      projectFinding(
        { projectName: "example/project" },
        { id: "https://git.example.test/example/project" },
      ),
    ]),
  ).toThrow("does not match");
  const host = "https://git.example.test/group/sub/project";
  for (const providerType of ["GITHUB", "GITLAB_SELF_MANAGED"])
    expect(() =>
      normalize(
        [projectFinding({ providerType, projectName: "group/sub/project" })],
        "https://gitlab.com/group/sub/project",
      ),
    ).toThrow("provider");
  expect(
    normalize(
      [
        projectFinding(
          {
            providerType: "GITLAB_SELF_MANAGED",
            projectName: "group/sub/project",
          },
          { id: host },
        ),
      ],
      host,
      "local",
    ).findings,
  ).toHaveLength(1);
  expect(() =>
    normalize(
      [
        projectFinding({
          providerType: "GITLAB_SELF_MANAGED",
          projectName: "Group/sub/project",
        }),
      ],
      host,
      "local",
    ),
  ).toThrow("does not match");
  expect(
    normalize([
      projectFinding({ projectName: "https://GITHUB.COM/EXAMPLE/PROJECT.git" }),
    ]).findings,
  ).toHaveLength(1);
});

test.each(["local", "cloud"] as const)(
  "binds a project ARN to its trusted host during %s normalization and replay",
  (target) => {
    const arn = `${inspectorIntegrationArn}/${inspectorProjectId}`;
    const urls = [
      "https://one.example.test/example/project",
      "https://two.example.test/example/project",
    ] as const;
    const slug = projectFinding({ projectName: "example/project" });
    const projectMap = new Map([[arn, urls[0]]]);
    const result = normalize([slug], urls[0], target, projectMap);
    const retained = result.findings[0]!.evidence.source_data!;
    expect(retained).toEqual({
      format: "aws-inspector2-list-findings/v1",
      sourceRepositoryUrl: urls[0],
      finding: slug,
    });
    expect(
      inspectorReportRepositories(result.findings, target, projectMap).get(
        slug.findingArn,
      )?.url,
    ).toBe(urls[0]);
    expect(() => normalize([slug], urls[1], target, projectMap)).toThrow(
      "mapping does not match",
    );
    expect(() =>
      normalize(
        [projectFinding({ projectName: urls[1] })],
        urls[1],
        target,
        projectMap,
      ),
    ).toThrow("mapping does not match");

    expect(() =>
      inspectorReportRepositories(
        result.findings,
        target,
        new Map([[arn, urls[1]]]),
      ),
    ).toThrow("mapping does not match");

    // Retained evidence cannot supply its own trusted binding on replay.
    retained["sourceRepositoryUrl"] = urls[1];
    retained["projectMap"] = { [arn]: urls[1] };
    expect(() => inspectorReportRepositories(result.findings, target)).toThrow(
      "native repository URL",
    );
    expect(() =>
      inspectorReportRepositories(result.findings, target, projectMap),
    ).toThrow("mapping does not match");
  },
);

test("only the full Inspector project resource ARN can authorize a URL", () => {
  const native = inspectorPackageFinding();
  const canonical = native.resources[0]!.details.codeRepository.projectName;
  const source = normalize([native], canonical, "local").findings;
  expect(() => inspectorReportRepositories(source, "local", new Map())).toThrow(
    "missing from the trusted mapping",
  );
  expect(() =>
    inspectorReportRepositories(
      [
        {
          source_finding_id: "opaque",
          evidence: { ...source[0]!.evidence, source_data: {} },
        },
      ],
      "local",
      new Map(),
    ),
  ).toThrow("retained Inspector");
  const slug = { projectName: "example/project" };
  for (const key of [
    inspectorProjectId,
    inspectorIntegrationArn,
    "example/project",
  ]) {
    const map = new Map([[key, inspectorRepositoryUrl]]);
    expect(() => normalize([native], canonical, "local", map)).toThrow(
      "missing from the trusted mapping",
    );
    expect(() =>
      normalize(
        [projectFinding(slug, { id: key })],
        inspectorRepositoryUrl,
        "local",
        map,
      ),
    ).toThrow();
  }
});

test("GitHub project slugs cannot identify a host; without a map, each destination needs native URL evidence", () => {
  const host = "https://git.example.test/Example/Project";
  const slug = projectFinding({ projectName: "EXAMPLE/PROJECT" });
  const nativeUrl = projectFinding({
    projectName: "https://GIT.EXAMPLE.TEST/example/project.git",
  });
  const tenantA = "https://tenant-a.ghe.com/example/project";
  const tenantB = "https://tenant-b.ghe.com/example/project";
  const tenantFinding = projectFinding({
    projectName: "https://TENANT-A.GHE.COM/Example/Project.git",
  });
  for (const target of ["local", "cloud"] as const) {
    const read = (finding: typeof slug, source = host) =>
      normalize([finding], source, target);
    const { findings } = read(tenantFinding, tenantA);
    const retained = findings[0]!.evidence.source_data!;
    expect(
      inspectorReportRepositories(findings, target).get(
        tenantFinding.findingArn,
      )?.url,
    ).toBe(tenantA);
    expect(() => read(tenantFinding, tenantB)).toThrow("does not match");
    retained["sourceRepositoryUrl"] = tenantB;
    expect(() => inspectorReportRepositories(findings, target)).toThrow(
      "does not match",
    );

    retained["finding"] = slug;
    for (const source of [
      inspectorRepositoryUrl,
      tenantA,
      tenantB,
      host,
      "https://github.com.example.test/example/project",
      "https://github.com:8443/example/project",
    ]) {
      expect(() => read(slug, source)).toThrow("native repository URL");
      retained["sourceRepositoryUrl"] = source;
      expect(() => inspectorReportRepositories(findings, target)).toThrow(
        "native repository URL",
      );
    }
    expect(read(nativeUrl).findings).toHaveLength(1);
    for (const other of [
      host.replace("git.", "other."),
      host.replace("https:", "http:"),
    ])
      expect(() => read(nativeUrl, other)).toThrow("does not match");

    for (const finding of [
      projectFinding({ projectName: "project" }, { id: host.toLowerCase() }),
      projectFinding({ projectName: undefined }, { id: host }),
    ])
      expect(read(finding).findings).toHaveLength(1);
    const unqualified = projectFinding({
      providerType: undefined,
      projectName: "example/project",
    });
    expect(() => read(unqualified, inspectorRepositoryUrl)).toThrow(
      "native repository URL",
    );
    const wrong = projectFinding({ projectName: "wrong" }, { id: host });
    expect(() => read(wrong)).toThrow("does not match");
  }
  const noProvider = projectFinding({
    projectName: host,
    providerType: undefined,
  });
  expect(normalize([noProvider], host, "local").findings).toHaveLength(1);
  expect(() => normalize([noProvider], host, "cloud")).toThrow(
    "GitHub repository provider",
  );
});

test("self-managed GitLab mappings require native host evidence and are local only", () => {
  const host = "https://git.example.test/group/project";
  const alias = "https://other.example.test/group/project";
  const native = projectFinding({
    providerType: "GITLAB_SELF_MANAGED",
    projectName: host,
  });
  const { findings } = normalize([native], host, "local");
  expect(
    inspectorReportRepositories(findings, "local").get(native.findingArn)?.url,
  ).toBe(host);
  expect(() => normalize([native], alias, "local")).toThrow("does not match");
  expect(() => normalize([native], host, "cloud")).toThrow("local only");
  expect(() => inspectorReportRepositories(findings, "cloud")).toThrow(
    "local only",
  );

  const slug = projectFinding({
    providerType: "GITLAB_SELF_MANAGED",
    projectName: "group/project",
  });
  const retained = findings[0]!.evidence.source_data!;
  retained["finding"] = slug;
  for (const source of [host, alias]) {
    expect(() => normalize([slug], source, "local")).toThrow(
      "native repository URL",
    );
    retained["sourceRepositoryUrl"] = source;
    expect(() => inspectorReportRepositories(findings, "local")).toThrow(
      "native repository URL",
    );
  }
});

test("uses the provider of the verified project regardless of finding order", () => {
  const enterprise = "https://git.example.test/example/project";
  for (const source of [inspectorRepositoryUrl, enterprise]) {
    const known = projectFinding({ projectName: source });
    const omitted = {
      ...projectFinding({ projectName: undefined, providerType: undefined }),
      findingArn: codeFinding().findingArn,
    };
    for (const target of ["local", "cloud"] as const) {
      for (const rows of [
        [known, omitted],
        [omitted, known],
      ]) {
        const output = normalize(rows, source, target);
        expect(output.findings).toHaveLength(2);
        expect([
          ...inspectorReportRepositories(output.findings, target).values(),
        ]).toEqual(rows.map(() => ({ url: source, platform: "github" })));
      }
    }
  }
});

test("a cloud exclusion cannot leave a ready row without the project's repository proof", () => {
  const source = "https://git.example.test/example/project";
  const known = {
    ...projectFinding({ projectName: source }),
    title: "a".repeat(513),
  };
  const dependent = {
    ...projectFinding({ projectName: undefined, providerType: undefined }),
    findingArn: codeFinding().findingArn,
  };
  for (const rows of [
    [known, dependent],
    [dependent, known],
  ]) {
    const output = normalize(rows, source, "cloud");
    expect(output.findings).toHaveLength(0);
    expect(output.excluded.map((row) => row.source_finding_id).sort()).toEqual(
      [known.findingArn, dependent.findingArn].sort(),
    );
    expect(
      output.excluded.find(
        (row) => row.source_finding_id === dependent.findingArn,
      )?.reason,
    ).toMatch(/provider|native repository URL/);
    expect(inspectorReportRepositories(output.findings, "cloud").size).toBe(0);
    expect(normalize(rows, source, "local").findings).toHaveLength(2);
  }
});

test("remaining findings can share native URL proof after the only provider hint is excluded", () => {
  const source = "https://scm.example.test/Owner/Repo";
  const row = (id: string, projectName: string, providerType?: string) => ({
    ...projectFinding({ projectName, providerType }),
    findingArn: inspectorPackageFinding().findingArn.replace(
      /a{32}$/u,
      id.repeat(32),
    ),
  });
  const duplicate = row("a", "Owner/Repo", "GITHUB");
  const exact = row("b", source);
  const slug = row("c", "Owner/Repo");
  const mismatch = row("d", "owner/repo");
  for (const valid of [
    [exact, slug],
    [slug, exact],
  ]) {
    const rows = [duplicate, mismatch, ...valid, duplicate];
    const result = normalize(rows, source, "local");
    expect(result.findings.map((item) => item.source_finding_id)).toEqual(
      valid.map((item) => item.findingArn),
    );
    expect(result.excluded.map((item) => item.position)).toEqual([1, 2, 5]);
    expect(inspectorReportRepositories(result.findings, "local").size).toBe(2);
    expect(normalize(rows, source, "cloud").findings).toHaveLength(0);
  }
});

test("compares exact native resource IDs and never treats opaque slash strings as namespace claims", () => {
  const opaqueId = "integrations/00001/projects/00002";
  const mapped = projectFinding(
    { projectName: inspectorRepositoryUrl },
    { id: opaqueId },
  );
  const duplicateProject = { ...mapped, findingArn: codeFinding().findingArn };
  expect(normalize([mapped, duplicateProject]).findings).toHaveLength(2);
  for (const projectName of [undefined, "project", "other/project"])
    expect(() =>
      normalize([projectFinding({ projectName }, { id: "example/project" })]),
    ).toThrow();
  for (const [firstId, otherId] of [
    ["example/project", "EXAMPLE/PROJECT"],
    [inspectorRepositoryUrl, inspectorRepositoryUrl.toUpperCase()],
    [opaqueId, "integrations/00002/projects/00002"],
  ] as const) {
    const first = projectFinding({}, { id: firstId });
    const other = {
      ...projectFinding({}, { id: otherId }),
      findingArn: duplicateProject.findingArn,
    };
    expect(() => normalize([first, other])).toThrow("more than one repository");
  }
  expect(() =>
    normalize([
      projectFinding(
        {},
        { id: "ssh://git@other.example.test/example/project" },
      ),
    ]),
  ).toThrow("HTTP(S)");
});

test("exposes GitHub remote semantics only from the validated native repository provider", () => {
  const host = "https://git.example.test/example/project";
  const known = projectFinding({ projectName: host });
  const { findings } = normalize([known], host, "local");
  const platform = () =>
    inspectorReportRepositories(findings, "local").get(known.findingArn)
      ?.platform;
  expect(platform()).toBe("github");

  const retained = findings[0]!.evidence.source_data!;
  retained["providerType"] = "GITHUB";
  for (const providerType of [undefined, "GITLAB_SELF_MANAGED"]) {
    retained["finding"] = projectFinding({ providerType, projectName: host });
    expect(platform()).toBeUndefined();
  }
  const noProvider = projectFinding({
    providerType: undefined,
    projectName: inspectorRepositoryUrl,
  });
  expect(
    inspectorReportRepositories(normalize([noProvider]).findings, "local").get(
      noProvider.findingArn,
    )?.platform,
  ).toBeUndefined();
});

test("checks native scope before discarding duplicates or unsupported finding types", () => {
  const first = inspectorPackageFinding();
  const anotherProject =
    inspectorIntegrationArn + "/project-33333333-3333-4333-8333-333333333333";
  expect(() =>
    normalize([
      first,
      {
        ...projectFinding({}, { id: anotherProject }),
        type: "NETWORK_REACHABILITY",
      },
    ]),
  ).toThrow("more than one repository");
  const other = projectFinding({}, { id: anotherProject });
  expect(() =>
    normalize([
      { ...first, resources: [...first.resources, ...other.resources] },
    ]),
  ).toThrow("more than one repository");
  expect(() =>
    normalize([first, projectFinding({ projectName: "other/project" })]),
  ).toThrow("does not match");
  expect(() => normalize([{ ...first, awsAccountId: "999999999999" }])).toThrow(
    "account",
  );
  for (const change of [
    {
      id:
        inspectorIntegrationArn.replace("us-east-1", "us-west-2") +
        "/" +
        inspectorProjectId,
    },
    { id: "arn:aws:ecr:us-east-1:123456789012:repository/example/project" },
    { providerAccountId: "999999999999" },
    { region: "us-west-2" },
    { partition: "aws-cn" },
  ])
    expect(() => normalize([projectFinding({}, change)])).toThrow();
  expect(() =>
    normalize([
      projectFinding({
        integrationArn: inspectorIntegrationArn.replace("11111111", "44444444"),
      }),
    ]),
  ).toThrow("integration");
  expect(() =>
    normalize([projectFinding({ providerType: "GITLAB_SELF_MANAGED" })]),
  ).toThrow("provider");
});

test.each(["cloud", "local"] as const)(
  "rejects forged Inspector evidence during %s replay",
  (target) => {
    const native = inspectorPackageFinding();
    const { findings } = normalize([native], inspectorRepositoryUrl, target);
    const row = findings[0]!;
    const retained = row.evidence.source_data!;
    const replay = () => inspectorReportRepositories(findings, target);
    row.source_finding_id = codeFinding().findingArn;
    expect(replay).toThrow("finding ARN");
    row.source_finding_id = native.findingArn;
    for (const [patch, message] of [
      [{ finding: codeFinding() }, "finding ARN"],
      [{ sourceRepositoryUrl: undefined }, "source-repository-url"],
      [
        { sourceRepositoryUrl: "https://github.com/other/project" },
        "does not match",
      ],
      [
        { finding: projectFinding({ projectName: "other/project" }) },
        "does not match",
      ],
      [{ finding: { ...native, resources: [] } }, "CODE_REPOSITORY"],
      [
        {
          finding: {
            ...native,
            resources: [...native.resources, { type: "AWS_EC2_INSTANCE" }],
          },
        },
        "CODE_REPOSITORY",
      ],
    ] as const) {
      row.evidence.source_data = { ...retained, ...patch };
      expect(replay).toThrow(message);
    }

    row.evidence.source_data = undefined;
    expect(replay).toThrow("retained Inspector");
    row.source_finding_id = "opaque";
    for (const sourceData of [
      undefined,
      { finding: "opaque", providerType: "GITHUB" },
    ]) {
      row.evidence.source_data = sourceData;
      expect(replay().size).toBe(0);
    }
  },
);

test("reads saved JSON and gzip without treating JSONL or damaged bytes as a successful empty export", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synthetic-inspector-"));
  try {
    const path = join(directory, "input.json");
    const report = inspectorReport();
    const expected = normalizeInspectorFindings(report, inspectorRepositoryUrl);
    for (const bytes of [
      Buffer.from(JSON.stringify(report)),
      gzipSync(JSON.stringify(report)),
    ]) {
      await writeFile(path, bytes);
      const map = new Map([
        [report.findings[0]!.resources[0]!.id, inspectorRepositoryUrl],
      ]);
      const reading = readInspectorFindings(
        path,
        inspectorRepositoryUrl,
        "cloud",
        map,
      );
      map.clear();
      expect(await reading).toEqual(expected);
    }
    await writeFile(path, '{"findings":[]}\n{"findings":[]}');
    await expect(
      readInspectorFindings(path, inspectorRepositoryUrl),
    ).rejects.toThrow("JSON");
    await writeFile(path, Buffer.from([0xff]));
    await expect(
      readInspectorFindings(path, inspectorRepositoryUrl),
    ).rejects.toThrow("UTF-8");
    report.findings[0]!.description = "x".repeat(65537);
    await writeFile(path, JSON.stringify(report));
    expect(
      (await readInspectorFindings(path, inspectorRepositoryUrl, "cloud"))
        .excluded,
    ).toHaveLength(1);
    expect(
      (await readInspectorFindings(path, inspectorRepositoryUrl, "local"))
        .findings,
    ).toHaveLength(1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
