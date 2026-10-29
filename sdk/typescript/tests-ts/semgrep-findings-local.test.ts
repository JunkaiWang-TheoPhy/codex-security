import { access, readFile, rm, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import {
  normalizeSemgrepSarif,
  readSemgrepFindings,
} from "../src/semgrep-findings.js";
import { normalizeSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  platformFinding,
  platformProject,
  collectProject,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const repositoryUrl = "https://github.com/example/project";
const formats = ["JSON", "SARIF"] as const;

async function platformCheckout(remote: string, sourceKey = "platform") {
  const fixture = await localFindingsFixture({ remote });
  return {
    file: join(fixture.root, "semgrep.json"),
    options: {
      repository: fixture.repository,
      provider: "semgrep" as const,
      sourceKey,
    },
    dependencies: { environment: fixture.environment },
    [Symbol.asyncDispose]: fixture.dispose,
  };
}

test("a retained Platform row binds mixed SARIF provenance in either order", async () => {
  const url = "https://scm.example.test/Team/Project";
  await using fixture = await platformCheckout(url);
  const { findings: platform } = normalizeSemgrepPlatformFindings({
    ...platformReport(),
    project: { ...platformProject, url },
    findings: [{ ...platformFinding(7), repository: { url } }],
  });
  const raw = semgrepSarif();
  const legacy = normalizeSemgrepSarif(
    {
      ...raw,
      runs: raw.runs.map((run) => ({
        ...run,
        versionControlProvenance: [{ repositoryUri: url.toLowerCase() }],
      })),
    },
    { sourceRepositoryUrl: url },
  );
  for (const findings of [
    [...legacy.findings, ...platform],
    [...platform, ...legacy.findings],
  ]) {
    const input = { read: findings.length, findings, excluded: [] };
    await expect(
      prepareNormalizedLocalImport(
        input,
        fixture.options,
        fixture.dependencies,
      ),
    ).rejects.toThrow("does not match");
    expect(
      (
        await prepareNormalizedLocalImport(input, fixture.options, {
          ...fixture.dependencies,
          sourceRepositories: [{ url, platform: "github" }],
        })
      ).preview.findings,
    ).toHaveLength(findings.length);
  }
});

test("a saved Platform collection replays and updates unassessed findings in SQLite", async () => {
  await using fixture = await platformCheckout(
    repositoryUrl,
    "example/project/main/platform",
  );
  const file = fixture.file + ".gz";
  const { options, dependencies } = fixture;
  const finding = platformFinding(17);
  for (const [index, status] of ["open", "open", "fixed"].entries()) {
    await writeFile(
      file,
      gzipSync(JSON.stringify(platformReport([{ ...finding, status }]))),
    );
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    const outcome = await prepared.import();
    expect(outcome.counts).toMatchObject({
      [["created", "unchanged", "updated"][index]!]: 1,
    });
  }
  const records = await listLocalExternalFindings(options, dependencies);
  expect(records).toHaveLength(1);
  expect(records[0]).toMatchObject({
    version: 2,
    assessment: { state: "not_assessed" },
    evidence: { details: { source_status: "fixed" } },
  });
});

test("replays native SSH evidence and URL-less labels from the selected Semgrep project", async () => {
  await using fixture = await platformCheckout(repositoryUrl);
  const project = {
    ...platformProject,
    name: "billing-module",
    url: "ssh://git@github.com/example/project.git",
  };
  const alias = "local_scan/backend";
  const rows = [
    { ...platformFinding(8), repository: { name: alias } },
    {
      ...platformFinding(9),
      repository: { url: "git@github.com:example/project.git" },
    },
  ];
  const collected = await collectProject(project, rows, repositoryUrl);
  expect(collected).toMatchObject({
    project,
    sourceRepositoryUrl: repositoryUrl,
    repositoryAliases: [alias],
    findings: rows,
  });
  const { file, options, dependencies } = fixture;
  await writeFile(file, JSON.stringify(collected));
  const prepared = await prepareLocalExternalImport(
    file,
    options,
    dependencies,
  );
  expect((await prepared.import()).counts.created).toBe(2);
  const stored = await listLocalExternalFindings(options, dependencies);
  expect(stored.map((entry) => entry.evidence.source_data)).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        repositoryAliases: [alias],
        project,
        finding: rows[0],
      }),
      expect.objectContaining({
        project,
        repositoryAliases: [],
        finding: rows[1],
      }),
    ]),
  );
  expect(() =>
    normalizeSemgrepPlatformFindings({ ...collected, repositoryAliases: [] }),
  ).toThrow("matching source repository");
  const normalized = normalizeSemgrepPlatformFindings(collected);
  const evidence = normalized.findings[1]!.evidence.source_data!;
  evidence["finding"] = {
    ...rows[1],
    repository: { url: repositoryUrl, name: "other-module" },
  };
  await expect(
    prepareNormalizedLocalImport(normalized, options, dependencies),
  ).rejects.toThrow("matching source repository");
  // Historical normalized evidence without captured labels accepted a matching repository URL.
  delete evidence["repositoryAliases"];
  expect(
    (await prepareNormalizedLocalImport(normalized, options, dependencies))
      .preview.findings,
  ).toHaveLength(2);
  for (const url of [
    "git@github.com:other/project.git",
    "ssh://deploy@github.com/example/project.git",
    "ssh://git@github.com:2222/example/project.git",
    "ssh://git@github.com?other/example/project.git",
    "ssh://git@github.com#other/example/project.git",
    "ssh://git@github.com%23other/example/project.git",
    "ssh://git@other.test%2Fextra@github.com/example/project.git",
    "git@scm.example.test:example/project.git",
  ]) {
    expect(() =>
      normalizeSemgrepPlatformFindings({
        ...collected,
        project: { ...project, url },
        sourceRepositoryUrl: url.includes("scm.example.test")
          ? "https://scm.example.test/example/project"
          : repositoryUrl,
      }),
    ).toThrow();
  }
});

test("hosted Semgrep honors an explicit Enterprise repository binding", async () => {
  const url = "https://scm.example.test/Team/Project";
  await using fixture = await platformCheckout(url.toLowerCase());
  const report = platformReport([]);
  const input = normalizeSemgrepPlatformFindings({
    ...report,
    project: { ...report.project, url },
  });
  const prepare = (source: { url: string; platform?: "github" }) =>
    prepareNormalizedLocalImport(input, fixture.options, {
      ...fixture.dependencies,
      sourceRepositories: [source],
    });
  await expect(prepare({ url: url.toLowerCase() })).rejects.toThrow(
    "does not match",
  );
  await expect(
    prepare({ url: url + "-other", platform: "github" }),
  ).rejects.toThrow("does not match");
  expect(
    (await prepare({ url: url.toLowerCase(), platform: "github" })).preview
      .findings,
  ).toEqual([]);
  input.sourceRepositoryPlatform = "other";
  await expect(
    prepare({ url: url.toLowerCase(), platform: "github" }),
  ).rejects.toThrow("does not match");

  const row = {
    ...platformFinding(7),
    repository: {
      name: "project",
      url: "git@scm.example.test:team/project.git",
    },
  };
  const collected = await collectProject(
    { ...report.project, url },
    [row],
    url.toLowerCase(),
  );
  expect(collected).toMatchObject({
    project: { url },
    sourceRepositoryUrl: url.toLowerCase(),
    findings: [row],
  });
  expect(() => normalizeSemgrepPlatformFindings(collected)).toThrow();
  await writeFile(fixture.file, JSON.stringify(collected));
  const prepareFile = (source?: { url: string; platform?: "github" }) =>
    prepareLocalExternalImport(
      fixture.file,
      { ...fixture.options, sourceRepositoryUrl: url.toLowerCase() },
      {
        ...fixture.dependencies,
        sourceRepositories: source ? [source] : [],
      },
    );
  await expect(prepareFile()).rejects.toThrow("does not match");
  await expect(
    prepareFile({ url: url + "-other", platform: "github" }),
  ).rejects.toThrow("does not match");
  expect(
    (await prepareFile({ url, platform: "github" })).preview.findings,
  ).toHaveLength(1);
  const ssh = "scm.example.test:team/project.git";
  expect(
    (await prepareFile({ url: "git@" + ssh, platform: "github" })).preview
      .findings,
  ).toHaveLength(1);
  await expect(
    prepareFile({ url: "other@" + ssh, platform: "github" }),
  ).rejects.toThrow("does not match");
});

test.each([
  "ssh://git@github.com/example/project.git?foreign",
  "ftp://github.com/example/project",
  "https::https://github.com/example/foreign.git",
  "http::ftp://github.com/example/project",
  "ssh://git@github.com/example/other/../project.git",
  "https://github.com/example/other/%2e%2e/project.git",
  "https://github.com/example\\project.git",
  "https://github.com/example%2Fproject.git",
  "https://github.com/example/project.git?other",
  "https://github.com:8443/example/project.git",
  "other@github.com:example/project.git",
  "git+ssh://other@github.com/example/project",
  "ssh+git://git@github.com:2222/example/project",
  "git+ssh://git@github.com/elsewhere/%2e%2e/example/project",
  "ssh+git://git@github.com/example/project.git#foreign",
])(
  "an empty Platform report rejects a checkout whose remote is %s",
  async (remote) => {
    await using fixture = await platformCheckout(remote);
    const { file, options, dependencies } = fixture;
    await writeFile(file, JSON.stringify(platformReport([])));
    await expect(
      prepareLocalExternalImport(file, options, dependencies),
    ).rejects.toThrow("does not match");
    await expect(
      prepareNormalizedLocalImport(
        await readSemgrepFindings(file),
        options,
        dependencies,
      ),
    ).rejects.toThrow("does not match");
  },
);

test.each([
  [
    repositoryUrl,
    "https://git@github.com:443/example/project.git",
    "https://github.com:443/example/project",
  ],
  ["https://github.com:443/example/project", repositoryUrl, repositoryUrl],
  [
    repositoryUrl,
    "ftps::https://github.com:443/example/project.git",
    "https://github.com:443/example/project",
  ],
  [
    "https://github.com:443/example/project",
    "git@github.com:example/project.git",
    repositoryUrl,
  ],
  [
    "https://github.com:443/example/archive.git.git",
    "git@github.com:example/archive.git.git",
    "https://github.com/example/archive.git.git",
  ],
  [
    "https://bitbucket.org/team/project",
    "git+ssh://git@bitbucket.org:22/team/project.git",
    "https://bitbucket.org:443/team/project",
  ],
  [
    "https://gitlab.com/Group/project",
    "ssh+git://git@gitlab.com/Group/project.git",
    "https://gitlab.com:443/Group/project",
  ],
])(
  "hosted %s matches the equivalent checkout %s while keeping explicit source ports distinct",
  async (url, remote, otherSource) => {
    await using fixture = await platformCheckout(remote);
    const report = platformReport([]);
    const input = normalizeSemgrepPlatformFindings({
      ...report,
      project: { ...report.project, url },
    });
    const { options, dependencies } = fixture;
    expect(
      (await prepareNormalizedLocalImport(input, options, dependencies)).preview
        .findings,
    ).toEqual([]);
    await expect(
      prepareNormalizedLocalImport(input, options, {
        ...dependencies,
        sourceRepositories: [{ url: otherSource }],
      }),
    ).rejects.toThrow("does not match");
  },
);

const gitlabUrl = "https://gitlab.com/Group/My-Repo";
const escapedGitlabUrl = "https://gitlab.com/%47roup/My%2dRepo";
test.each([
  [escapedGitlabUrl, gitlabUrl],
  [gitlabUrl, escapedGitlabUrl],
  [escapedGitlabUrl, "ssh://git@gitlab.com/Group/My-Repo.git"],
])(
  "hosted source %s and checkout %s compare unreserved path escapes",
  async (source, remote) => {
    await using fixture = await platformCheckout(remote);
    const report = platformReport([
      { ...platformFinding(7), repository: { url: source } },
    ]);
    const input = normalizeSemgrepPlatformFindings({
      ...report,
      project: { ...report.project, url: source },
    });
    input.findings[0]!.evidence.details!.repository!.url = gitlabUrl;
    const prepare = (url: string) =>
      prepareNormalizedLocalImport(input, fixture.options, {
        ...fixture.dependencies,
        sourceRepositories: [{ url }],
      });
    expect((await prepare(gitlabUrl)).preview.findings).toHaveLength(1);
    await expect(prepare("https://gitlab.com/Group%2FMy-Repo")).rejects.toThrow(
      "does not match",
    );
    await expect(prepare("https://gitlab.com/group/My-Repo")).rejects.toThrow(
      "does not match",
    );
  },
);

function report(
  format: (typeof formats)[number],
  {
    line = 3,
    fingerprint = "synthetic-fingerprint",
    message = "Synthetic finding",
    sparse = false,
  } = {},
) {
  if (format === "JSON") {
    const input = semgrepJson();
    const result = input.results[0]!;
    result.start.line = line;
    result.end.line = line;
    result.extra.fingerprint = fingerprint;
    result.extra.message = message;
    if (sparse) {
      result.path = "../outside.ts";
      result.extra.severity = "EXPERIMENT";
      result.extra.lines = "requires login";
    }
    return input;
  }
  const input = semgrepSarif();
  const run = input.runs[0]!;
  const result = run.results[0]!;
  const region = result.locations[0]!.physicalLocation.region;
  region.startLine = line;
  region.endLine = line;
  result.fingerprints["matchBasedId/v1"] = fingerprint;
  result.message.text = message;
  if (sparse) {
    result.locations[0]!.physicalLocation.artifactLocation.uri =
      "../outside.ts";
    run.tool.driver.rules[0]!.defaultConfiguration.level = "none";
  }
  return input;
}

test("Semgrep file reader rejects malformed SARIF repository provenance", async () => {
  const directory = await temporaryDirectory("semgrep-reader-");
  try {
    const file = join(directory, "semgrep.sarif");
    const input = sarifWithRepositories(['http://""?\nX']);
    await writeFile(file, JSON.stringify(input));
    await expect(
      readSemgrepFindings(file, { sourceRepositoryUrl: repositoryUrl }),
    ).rejects.toThrow(
      "SARIF source repository does not match the declared source repository URL.",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

for (const suppliedFingerprint of [true, false]) {
  test.each(formats)(
    `Semgrep %s movement ${suppliedFingerprint ? "updates the supplied fingerprint" : "retains both fallback records"} in SQLite`,
    async (format) => {
      const fixture = await localFindingsFixture({ remote: repositoryUrl });
      try {
        const file = join(fixture.root, "semgrep.json");
        const options = {
          repository: fixture.repository,
          provider: "semgrep" as const,
          sourceKey: "example-project:main",
          sourceRepositoryUrl: repositoryUrl,
        };
        const dependencies = { environment: fixture.environment };
        const fingerprint = suppliedFingerprint
          ? "synthetic-fingerprint"
          : "requires login";
        async function prepareLine(line: number, message?: string) {
          await writeFile(
            file,
            JSON.stringify(report(format, { line, fingerprint, message })),
          );
          return prepareLocalExternalImport(file, options, dependencies);
        }

        const prepared = await prepareLine(3);
        expect(prepared.preview.findings).toHaveLength(1);
        expect(prepared.preview.excluded).toEqual([]);
        expect(prepared.preview.source).toEqual({
          provider: "semgrep",
          source_key: options.sourceKey,
        });
        expect((await prepared.import()).counts).toEqual({
          created: 1,
          updated: 0,
          unchanged: 0,
        });
        const [original] = await listLocalExternalFindings(
          options,
          dependencies,
        );
        expect(original).toMatchObject({
          provider: "semgrep",
          sourceKey: options.sourceKey,
          sourceFindingId: prepared.preview.findings[0]!.source_finding_id,
          assessment: { state: "not_assessed" },
          version: 1,
        });
        expect(original!.evidence).toEqual(
          prepared.preview.findings[0]!.evidence,
        );
        expect(original!.evidence).not.toHaveProperty("confidence");
        expect(original!.evidence.locations).toEqual([
          { path: "src/example.ts", line: 3 },
        ]);

        const next = await prepareLine(9);
        expect((await next.import()).counts).toEqual(
          suppliedFingerprint
            ? { created: 0, updated: 1, unchanged: 0 }
            : { created: 1, updated: 0, unchanged: 0 },
        );
        const records = await listLocalExternalFindings(options, dependencies);
        const moved = records.find(
          (record) => record.evidence.locations?.[0]?.line === 9,
        );
        expect(moved).toBeDefined();
        expect(moved!.evidence.locations).toEqual([
          { path: "src/example.ts", line: 9 },
        ]);
        expect(moved!.evidence.source_data?.["result"]).toMatchObject(
          format === "JSON"
            ? { extra: { fingerprint } }
            : { fingerprints: { "matchBasedId/v1": fingerprint } },
        );
        expect(moved!.assessment).toEqual({ state: "not_assessed" });
        if (suppliedFingerprint) {
          expect(records).toHaveLength(1);
          expect(moved).toMatchObject({
            id: original!.id,
            sourceFindingId: original!.sourceFindingId,
            createdAt: original!.createdAt,
            version: 2,
          });
        } else {
          expect(records).toHaveLength(2);
          expect(records.find((record) => record.id === original!.id)).toEqual(
            original,
          );
          expect(moved!.sourceFindingId).not.toBe(original!.sourceFindingId);
          expect(moved!.version).toBe(1);
        }
        const repeated = await prepareLocalExternalImport(
          file,
          options,
          dependencies,
        );
        expect((await repeated.import()).counts).toEqual({
          created: 0,
          updated: 0,
          unchanged: 1,
        });
        expect(await listLocalExternalFindings(options, dependencies)).toEqual(
          records,
        );

        if (suppliedFingerprint) {
          const edited = await prepareLine(9, "Updated scanner evidence");
          expect((await edited.import()).counts).toEqual({
            created: 0,
            updated: 1,
            unchanged: 0,
          });
          const updated = await listLocalExternalFindings(
            options,
            dependencies,
          );
          expect(updated).toHaveLength(1);
          expect(updated[0]).toMatchObject({
            id: original!.id,
            sourceFindingId: original!.sourceFindingId,
            createdAt: original!.createdAt,
            assessment: { state: "not_assessed" },
            version: 3,
          });
          expect(updated[0]!.evidence).toEqual(
            edited.preview.findings[0]!.evidence,
          );
          expect(updated[0]!.evidence.description).toBe(
            "Updated scanner evidence",
          );
        }
      } finally {
        await fixture.dispose();
      }
    },
  );
}

test.each(formats)(
  "Semgrep %s preserves sparse evidence without inventing a repository location or assessment",
  async (format) => {
    const fixture = await localFindingsFixture({ remote: repositoryUrl });
    try {
      const file = join(fixture.root, "semgrep.json");
      await writeFile(
        file,
        JSON.stringify(report(format, { message: "", sparse: true })),
      );
      const options = {
        repository: fixture.repository,
        provider: "semgrep" as const,
        sourceKey: "example-project:main",
        sourceRepositoryUrl: repositoryUrl,
      };
      const dependencies = { environment: fixture.environment };
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect((await prepared.import()).counts.created).toBe(1);
      const [stored] = await listLocalExternalFindings(options, dependencies);
      expect(stored!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
      expect(stored!.evidence).toMatchObject({
        description: null,
        severity: "unknown",
        locations: [],
        code_revision: null,
        details: { code: { end_line: null, snippet: null } },
      });
      expect(stored!.evidence.source_data).toHaveProperty("result");
      expect(stored!.evidence).not.toHaveProperty("confidence");
      expect(stored!.evidence).not.toHaveProperty("remediation");
      expect(stored!.assessment).toEqual({ state: "not_assessed" });
    } finally {
      await fixture.dispose();
    }
  },
);

test.each(formats)(
  "Semgrep %s rejects a source repository that conflicts with the selected checkout",
  async (format) => {
    const fixture = await localFindingsFixture({ remote: repositoryUrl });
    try {
      const file = join(fixture.root, "semgrep.json");
      await writeFile(file, JSON.stringify(report(format)));
      const dependencies = { environment: fixture.environment };
      await expect(
        prepareLocalExternalImport(
          file,
          {
            repository: fixture.repository,
            provider: "semgrep",
            sourceKey: "example-project:main",
            sourceRepositoryUrl: "https://github.com/other/project",
          },
          dependencies,
        ),
      ).rejects.toThrow("does not match");
      expect(
        await listLocalExternalFindings(
          { repository: fixture.repository },
          dependencies,
        ),
      ).toEqual([]);
    } finally {
      await fixture.dispose();
    }
  },
);

function sarifWithRepositories(urls: string[]) {
  const input = semgrepSarif();
  return {
    ...input,
    runs: [
      {
        ...input.runs[0]!,
        versionControlProvenance: urls.map((repositoryUri) => ({
          repositoryUri,
        })),
      },
    ],
  };
}

test.each([
  ["unknown host", "git.example.test", "with remote"],
  ["GitHub", "github.com", "with remote"],
  ["known GitHub custom host", "git.example.test", "with remote"],
  ["GitHub", "github.com", "with uppercase remote"],
  ["known GitHub custom host", "git.example.test", "with uppercase remote"],
  ["unknown host", "git.example.test", "without remote"],
  ["GitHub", "github.com", "without remote"],
  ["known GitHub custom host", "git.example.test", "without remote"],
])(
  "Semgrep SARIF preserves original repository references on %s (%s, %s)",
  async (platform, host, checkout) => {
    const sourceRepositoryUrl = `https://${host}/team/project`;
    const originalUrl = `https://${host}/Team/Project`;
    const fixture = await localFindingsFixture(
      checkout === "without remote"
        ? {}
        : {
            remote: `git@${host}:${checkout === "with uppercase remote" ? "Team/Project" : "team/project"}.git`,
          },
    );
    try {
      const file = join(fixture.root, "semgrep-report");
      const options = {
        repository: fixture.repository,
        provider: "semgrep" as const,
        sourceKey: "example-project:main",
        sourceRepositoryUrl,
      };
      const dependencies = {
        environment: fixture.environment,
        ...(platform === "known GitHub custom host"
          ? {
              sourceRepositories: [
                { url: originalUrl, platform: "github" as const },
              ],
            }
          : {}),
      };
      const database = join(fixture.stateDirectory, "workbench.sqlite3");
      async function writeReport(url: string, compressed = false) {
        // Keep both refs: checking only the first would miss the case-distinct one.
        const contents = JSON.stringify(
          sarifWithRepositories([sourceRepositoryUrl, url]),
        );
        await writeFile(file, compressed ? gzipSync(contents) : contents);
      }
      await writeReport(originalUrl, true);
      if (platform === "unknown host") {
        await expect(
          prepareLocalExternalImport(file, options, dependencies),
        ).rejects.toThrow("does not match");
        await expect(access(database)).rejects.toThrow();
        await writeReport(sourceRepositoryUrl);
      }
      const parsed = await readSemgrepFindings(file, { sourceRepositoryUrl });
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.findings).toEqual(parsed.findings);
      expect((await prepared.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });
      const stored = await listLocalExternalFindings(options, dependencies);
      expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
      expect(stored[0]!.evidence.details?.repository?.url).toBe(
        sourceRepositoryUrl,
      );
      expect(stored[0]!.evidence.source_data?.["runContext"]).toMatchObject({
        versionControlProvenance: [
          { repositoryUri: sourceRepositoryUrl },
          {
            repositoryUri:
              platform === "unknown host" ? sourceRepositoryUrl : originalUrl,
          },
        ],
      });
      expect(
        (
          await (
            await prepareLocalExternalImport(file, options, dependencies)
          ).import()
        ).counts,
      ).toEqual({ created: 0, updated: 0, unchanged: 1 });
      const before = await readFile(database);
      await writeReport(
        platform === "unknown host"
          ? originalUrl
          : `https://${host}/other/project`,
      );
      await expect(
        prepareLocalExternalImport(file, options, dependencies),
      ).rejects.toThrow("does not match");
      expect(await readFile(database)).toEqual(before);
      expect(await listLocalExternalFindings(options, dependencies)).toEqual(
        stored,
      );
    } finally {
      await fixture.dispose();
    }
  },
);

test("normalized Semgrep SDK imports retain original SARIF repository metadata through the explicit dependency", async () => {
  const sourceRepositoryUrl = "https://git.example.test/team/project";
  const originalUrl = "https://git.example.test/Team/Project";
  const fixture = await localFindingsFixture({ remote: sourceRepositoryUrl });
  try {
    const options = {
      repository: fixture.repository,
      provider: "semgrep" as const,
      sourceKey: "example-project:main",
    };
    const parsed = normalizeSemgrepSarif(sarifWithRepositories([originalUrl]), {
      sourceRepositoryUrl,
    });
    const saved = JSON.parse(JSON.stringify(parsed));
    await expect(
      prepareNormalizedLocalImport(saved, options, {
        environment: fixture.environment,
        sourceRepositories: [{ url: originalUrl }],
      }),
    ).rejects.toThrow("does not match");
    await expect(
      access(join(fixture.stateDirectory, "workbench.sqlite3")),
    ).rejects.toThrow();
    const dependencies = {
      environment: fixture.environment,
      sourceRepositories: [{ url: originalUrl, platform: "github" as const }],
    };
    const prepared = await prepareNormalizedLocalImport(
      saved,
      options,
      dependencies,
    );
    expect((await prepared.import()).counts.created).toBe(1);
    expect(
      (await listLocalExternalFindings(options, dependencies))[0]!.evidence,
    ).toEqual(parsed.findings[0]!.evidence);
  } finally {
    await fixture.dispose();
  }
});

test("Semgrep gzipped JSON uses the caller source URL without treating rule metadata as repository provenance", async () => {
  const sourceRepositoryUrl = "https://git.example.test/Team/Project";
  const fixture = await localFindingsFixture({
    remote: "git@git.example.test:Team/Project.git",
  });
  try {
    const input = semgrepJson();
    const first = input.results[0]!;
    const report = {
      ...input,
      results: [
        {
          ...first,
          extra: {
            ...first.extra,
            metadata: {
              ...first.extra.metadata,
              source: "https://rules.example.test/Other/Repository",
            },
          },
        },
      ],
    };
    const file = join(fixture.root, "semgrep-report");
    await writeFile(file, gzipSync(JSON.stringify(report)));
    const options = {
      repository: fixture.repository,
      provider: "semgrep" as const,
      sourceKey: "example-project:main",
      sourceRepositoryUrl,
    };
    const dependencies = { environment: fixture.environment };
    const parsed = await readSemgrepFindings(file, { sourceRepositoryUrl });
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect((await prepared.import()).counts.created).toBe(1);
    const stored = await listLocalExternalFindings(options, dependencies);
    expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
    await expect(
      prepareLocalExternalImport(
        file,
        {
          ...options,
          sourceRepositoryUrl: "https://git.example.test/team/project",
        },
        dependencies,
      ),
    ).rejects.toThrow("does not match");
    expect(await listLocalExternalFindings(options, dependencies)).toEqual(
      stored,
    );
  } finally {
    await fixture.dispose();
  }
});
