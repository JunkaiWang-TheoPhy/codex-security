import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  blackDuckEvidenceRepositoryUrls,
  normalizeBlackDuckFindings,
  readBlackDuckFindings,
} from "../src/blackduck-findings.js";
import {
  blackDuckBomReport,
  blackDuckBomRow,
} from "./support/blackduck-import-fixtures.js";

const repository = "https://vcs.example.test/team/application";

test("retains the complete BOM row, project version and caller's repository, not a fix or assessment", () => {
  const row = {
    ...blackDuckBomRow(),
    ignored: true,
    packageUrl: "pkg:maven/example/library@1.0",
    license: { licenseDisplay: "Example license" },
    vulnerabilityWithRemediation: {
      ...blackDuckBomRow().vulnerabilityWithRemediation,
      remediationStatus: "REMEDIATION_COMPLETE",
      description: "Vendor description",
      cweId: "CWE-79",
      relatedVulnerability: "CVE-2099-1000",
      vulnerabilityUpdatedDate: "2026-01-01T00:00:00Z",
      extension: { values: [42] },
    },
  };
  const input = {
    ...blackDuckBomReport([row]),
    appliedFilters: ["ignored:true"],
  };
  const original = structuredClone(row);
  const result = normalizeBlackDuckFindings(input, repository);
  expect(result).toEqual(normalizeBlackDuckFindings([row], repository));
  expect(result).toEqual(
    normalizeBlackDuckFindings(input, repository, "local"),
  );
  expect(result.excluded).toEqual([]);
  const evidence = result.findings[0]!.evidence;
  expect(evidence).toMatchObject({
    severity: "high",
    description: "Vendor description",
    advisory_ids: ["BDSA-2099-0001"],
    packages: [
      {
        name: "Example Library",
        ecosystem: "maven",
        installed_version: "1.0",
        fixed_versions: [],
        manifest_path: null,
      },
    ],
    locations: [],
    source_updated_at: null,
  });
  expect(evidence.source_data).toEqual({
    sourceRepositoryUrl: repository,
    projectVersionUrl:
      "https://scanner.example.test/api/projects/project-a/versions/release-a",
    row: original,
  });
  expect(evidence.details).toBeUndefined();
  evidence.details = {
    kind: "sast",
    repository: { url: "https://vcs.example.test/team/elsewhere" },
  };
  expect(blackDuckEvidenceRepositoryUrls(evidence.source_data)).toEqual([
    repository,
  ]);
  row.vulnerabilityWithRemediation.extension.values.push(99);
  expect(evidence.source_data?.["row"]).toEqual(original);
});

test("adding or omitting an unrelated row and changing collection paging metadata do not version retained evidence", () => {
  const row = blackDuckBomRow();
  const other = blackDuckBomRow("BDSA-2099-0002");
  const report = blackDuckBomReport([row, other]);
  report._meta.href += "?offset=0&limit=250";
  for (const target of ["cloud", "local"] as const) {
    const retained = normalizeBlackDuckFindings([row], repository, target)
      .findings[0];
    expect(
      normalizeBlackDuckFindings(report, repository, target).findings[0],
    ).toEqual(retained);
    expect(
      normalizeBlackDuckFindings(blackDuckBomReport([row]), repository, target)
        .findings[0],
    ).toEqual(retained);
  }
});

test("only a complete project-version collection can establish an empty selection", () => {
  const empty = blackDuckBomReport([]);
  expect(normalizeBlackDuckFindings(empty, repository)).toEqual({
    read: 0,
    findings: [],
    excluded: [],
  });
  for (const totalCount of [5, -1, "0", null, undefined])
    expect(() =>
      normalizeBlackDuckFindings({ ...empty, totalCount }, repository),
    ).toThrow(/totalCount/);
  for (const input of [
    [],
    {},
    { items: [], totalCount: 0 },
    { scanStatus: "SUCCESS" },
  ])
    expect(() => normalizeBlackDuckFindings(input, repository)).toThrow();
  for (const suffix of ["?offset=1", "?offset=0&offset=3"])
    expect(() =>
      normalizeBlackDuckFindings(
        { ...empty, _meta: { href: empty._meta.href + suffix } },
        repository,
      ),
    ).toThrow(/page/);
  for (const rel of ["next", "prev"])
    expect(() =>
      normalizeBlackDuckFindings(
        {
          ...empty,
          _meta: {
            ...empty._meta,
            links: [{ rel, href: "https://elsewhere.example.test/page" }],
          },
        },
        repository,
      ),
    ).toThrow(/page/);
  expect(() =>
    normalizeBlackDuckFindings(
      {
        ...empty,
        _meta: {
          href: empty._meta.href.replace(
            "vulnerable-bom-components",
            "components",
          ),
        },
      },
      repository,
    ),
  ).toThrow(/vulnerable-bom-components/);
});

test("selected array replay keeps distinct advisories, origins and sources; evidence edits keep identity", () => {
  const first = blackDuckBomRow();
  const second = blackDuckBomRow("BDSA-2099-0002");
  const alternateSource = {
    ...first,
    vulnerabilityWithRemediation: {
      ...first.vulnerabilityWithRemediation,
      source: "NVD",
    },
  };
  const alternateOrigin = blackDuckBomRow();
  alternateOrigin._meta.links[0]!.href =
    alternateOrigin._meta.links[0]!.href.replace("origin-a", "origin-b");
  const rows = [first, second, alternateSource, alternateOrigin];
  const result = normalizeBlackDuckFindings(
    blackDuckBomReport(rows),
    repository,
  );
  const ids = result.findings.map((finding) => finding.source_finding_id);
  expect(new Set(ids).size).toBe(4);
  first.vulnerabilityWithRemediation.severity = "LOW";
  first.vulnerabilityWithRemediation.remediationStatus = "IGNORED";
  const selection = normalizeBlackDuckFindings(rows.toReversed(), repository);
  expect(
    selection.findings.map((finding) => finding.source_finding_id),
  ).toEqual(ids.toReversed());
  expect(
    selection.findings.map(({ evidence }) => evidence.source_data?.["row"]),
  ).toEqual(rows.toReversed());
  expect(selection.findings.at(-1)!.evidence.severity).toBe("low");
  const duplicated = normalizeBlackDuckFindings(
    [first, second, first],
    repository,
  );
  expect(duplicated.findings).toHaveLength(1);
  expect(() =>
    normalizeBlackDuckFindings(
      blackDuckBomReport([first, second, first]),
      repository,
    ),
  ).toThrow(/pages may overlap/i);
  expect(
    duplicated.excluded.map(({ position, source_finding_id }) => [
      position,
      source_finding_id,
    ]),
  ).toEqual([
    [1, ids[0]!],
    [3, ids[0]!],
  ]);
});

test("collection and every selected occurrence must identify the same server, project and version", () => {
  const row = blackDuckBomRow();
  for (const key of ["scanner.example.test", "project-a", "release-a"]) {
    const other = blackDuckBomRow();
    other._meta.links[0]!.href = other._meta.links[0]!.href.replace(
      key,
      "other",
    );
    for (const input of [
      blackDuckBomReport([other]),
      [row, other],
      [other, row],
    ])
      expect(() => normalizeBlackDuckFindings(input, repository)).toThrow(
        /same project version/,
      );
  }
  const envelope = blackDuckBomReport([row]);
  envelope._meta.href = envelope._meta.href.replace("/projects/", "/project/");
  expect(
    normalizeBlackDuckFindings(envelope, repository).findings[0]!
      .source_finding_id,
  ).toBe(
    normalizeBlackDuckFindings([row], repository).findings[0]!
      .source_finding_id,
  );
  const origin = {
    rel: "vulnerabilities",
    href: `${row.componentVersion}/origin/origin-a/vulnerabilities`,
  };
  const unscoped = { ...row, _meta: { links: [origin] } };
  expect(() => normalizeBlackDuckFindings([row, unscoped], repository)).toThrow(
    /Each selected/,
  );
  expect(
    normalizeBlackDuckFindings(blackDuckBomReport([unscoped]), repository)
      .findings[0]!.source_finding_id,
  ).toBe(
    normalizeBlackDuckFindings([row], repository).findings[0]!
      .source_finding_id,
  );
  row._meta.links.push({
    ...origin,
    href: origin.href.replace("origin-a", "origin-b"),
  });
  expect(
    normalizeBlackDuckFindings([row], repository).excluded[0]!.reason,
  ).toMatch(/unambiguous/);
});

test("invalid components and non-vulnerability rows are diagnosed without inventing occurrences", () => {
  const row = blackDuckBomRow();
  const report = blackDuckBomReport();
  const noOrigin = { ...row, _meta: { links: [] } };
  const result = normalizeBlackDuckFindings(
    {
      ...report,
      items: [
        row,
        { license: {} },
        { policyStatus: "IN_VIOLATION" },
        {
          ...row,
          componentVersion: row.componentVersion.replace(
            "component-a",
            "component-b",
          ),
        },
        noOrigin,
      ],
      totalCount: 5,
    },
    repository,
  );
  expect(result.findings).toHaveLength(1);
  expect(result.excluded.map(({ position }) => position)).toEqual([2, 3, 4, 5]);
  expect(result.excluded.map(({ reason }) => reason)).toEqual([
    expect.stringContaining("vulnerabilityWithRemediation"),
    expect.stringContaining("vulnerabilityWithRemediation"),
    expect.stringContaining("contradicts"),
    expect.stringContaining("origin"),
  ]);
  const large = { ...row, extra: "x".repeat(270_000) };
  expect(normalizeBlackDuckFindings([large], repository).excluded).toHaveLength(
    1,
  );
  expect(
    normalizeBlackDuckFindings([large], repository, "local").findings[0]!
      .evidence.source_data?.["row"],
  ).toEqual(large);
});

test.each([
  "",
  "not a URL",
  "file:///team/repo",
  "https:vcs.example.test/team/repo",
  "https://vcs.example.test",
  "https://vcs.example.test/",
  "https://vcs.example.test/team/",
  "https://@vcs.example.test/team/repo",
  "https://user:password@vcs.example.test/team/repo",
  `${repository}?token=example`,
  `${repository}#branch`,
  `${repository}?`,
  `${repository}#`,
  "https://vcs.example.test/team//repo",
  "https://vcs.example.test/team/./repo",
  "https://vcs.example.test/team/../repo",
  "https://vcs.example.test/team/.git",
  "https://vcs.example.test/team/...git",
  "https://vcs.example.test/team/%2e%2E/repo",
  "https://vcs.example.test/team/%252e%252e/repo",
  `${repository}\\other`,
  `${repository}%2Fother`,
  `${repository}%5cother`,
  `${repository}%00`,
  `${repository}%3Fbranch`,
  `${repository}%23branch`,
  `${repository}%zz`,
  "https://vcs.example.test/team/%20",
])("rejects ambiguous repository binding %j even without rows", (source) => {
  expect(() =>
    normalizeBlackDuckFindings(blackDuckBomReport([]), source),
  ).toThrow(/source-repository-url/);
  expect(() =>
    blackDuckEvidenceRepositoryUrls({ sourceRepositoryUrl: source }),
  ).toThrow(/source-repository-url/);
});

test("accepts a nested repository URL and retains it independently of the mutable evidence projection", () => {
  const url =
    "http://vcs.example.test:8080/org/subgroup/Example%20Repository.git/";
  const data = normalizeBlackDuckFindings([blackDuckBomRow()], url).findings[0]!
    .evidence.source_data;
  expect(blackDuckEvidenceRepositoryUrls(data)).toEqual([url]);
  const otherComponent = blackDuckBomRow();
  otherComponent.componentVersion = otherComponent.componentVersion.replace(
    "component-a",
    "component-b",
  );
  expect(() =>
    blackDuckEvidenceRepositoryUrls({ ...data, row: otherComponent }),
  ).toThrow(/contradicts/);
  expect(() =>
    blackDuckEvidenceRepositoryUrls({
      projectVersionUrl: data?.["projectVersionUrl"],
    }),
  ).toThrow(/source-repository-url/);
  expect(blackDuckEvidenceRepositoryUrls({ arbitrary: "value" })).toEqual([]);
  expect(blackDuckEvidenceRepositoryUrls(undefined)).toEqual([]);
  expect(() =>
    blackDuckEvidenceRepositoryUrls({ row: blackDuckBomRow() }),
  ).toThrow(/source-repository-url/);
  const row = blackDuckBomRow();
  expect(() =>
    blackDuckEvidenceRepositoryUrls({
      sourceRepositoryUrl: repository,
      projectVersionUrl:
        "https://scanner.example.test/api/projects/project-a/versions/release-b",
      row,
    }),
  ).toThrow(/same project version/);
  row.vulnerabilityWithRemediation.source = "UNRECOGNIZED";
  expect(
    normalizeBlackDuckFindings([row], repository).excluded[0]!.reason,
  ).toMatch(/advisory source/);
});

test("normalized input cannot relabel one native occurrence with another finding's ID", () => {
  const [first, second] = normalizeBlackDuckFindings(
    [blackDuckBomRow(), blackDuckBomRow("BDSA-2099-0002")],
    repository,
  ).findings;
  const data = first!.evidence.source_data;
  expect(
    blackDuckEvidenceRepositoryUrls(data, first!.source_finding_id),
  ).toEqual([repository]);
  expect(() =>
    blackDuckEvidenceRepositoryUrls(data, second!.source_finding_id),
  ).toThrow(/source finding ID/);
  expect(() =>
    blackDuckEvidenceRepositoryUrls(
      { ...data, row: null },
      second!.source_finding_id,
    ),
  ).toThrow();
  expect(
    blackDuckEvidenceRepositoryUrls(
      { arbitrary: true },
      second!.source_finding_id,
    ),
  ).toEqual([]);
});

test("reads JSON and gzip by content and rejects a truncated collection in either target", async () => {
  const directory = await mkdtemp(join(tmpdir(), "blackduck-bom-"));
  try {
    const path = join(directory, "report");
    const items = [blackDuckBomRow(), blackDuckBomRow("BDSA-2099-0002")];
    const expected = normalizeBlackDuckFindings(items, repository);
    for (const bytes of [
      Buffer.from(JSON.stringify(items)),
      gzipSync(JSON.stringify(items)),
    ]) {
      await writeFile(path, bytes);
      for (const target of ["cloud", "local"] as const)
        expect(await readBlackDuckFindings(path, repository, target)).toEqual(
          expected,
        );
    }
    await writeFile(
      path,
      JSON.stringify({ ...blackDuckBomReport(items), totalCount: 5 }),
    );
    for (const target of ["cloud", "local"] as const)
      await expect(
        readBlackDuckFindings(path, repository, target),
      ).rejects.toThrow(/totalCount/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
