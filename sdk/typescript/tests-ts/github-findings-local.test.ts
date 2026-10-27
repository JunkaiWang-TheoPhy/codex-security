import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  githubFindingRepositoryUrl,
  readGitHubFindings,
} from "../src/github-findings.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  dependabotAlert,
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";

const fixtures: Awaited<ReturnType<typeof localFindingsFixture>>[] = [];
afterEach(async () => {
  for (const fixture of fixtures.splice(0)) await fixture.dispose();
});

test("Dependabot reports retain missing manifest and fix information and exclude conflicting subjects", async () => {
  const fixture = await localFindingsFixture();
  fixtures.push(fixture);
  const file = join(fixture.root, "selected.json");
  const alert = dependabotAlert();
  const badPackage = dependabotAlert(18);
  badPackage.security_vulnerability.package.name = "another-package";
  const badSubject = {
    ...dependabotAlert(19),
    repository: { full_name: "example/other" },
  };
  await writeFile(
    file,
    JSON.stringify([
      {
        ...alert,
        dependency: {},
        security_vulnerability: {
          ...alert.security_vulnerability,
          first_patched_version: null,
        },
      },
      badPackage,
      badSubject,
      { ...dependabotAlert(20), url: dependabotAlert(21).url },
    ]),
  );
  const parsed = await readGitHubFindings(file);
  expect(parsed.excluded.map((row) => row.position)).toEqual([2, 3, 4]);
  const evidence = parsed.findings[0]!.evidence;
  expect(evidence).toMatchObject({
    locations: [],
    packages: [
      { fixed_versions: [], manifest_path: null, installed_version: null },
    ],
  });
  // A normalized SDK caller can also supply typed provenance.
  expect(() =>
    githubFindingRepositoryUrl({
      ...evidence,
      details: {
        kind: "sast",
        repository: { url: "https://github.com/example/other" },
      },
    }),
  ).toThrow("conflicts");
});

type Source = "code-scanning" | "repository-advisory" | "global-advisory";

function githubSource(source: Source) {
  return source === "code-scanning"
    ? importedAlert()
    : importedAdvisory(source === "global-advisory" ? "global" : "repository");
}

test.each(["code-scanning", "repository-advisory", "global-advisory"] as const)(
  "GitHub %s imports into local storage and updates source evidence without assessing it",
  async (kind) => {
    const fixture = await localFindingsFixture({
      remote: "https://github.com/example/project",
    });
    fixtures.push(fixture);
    const source = githubSource(kind);
    const file = join(fixture.root, "github.json");
    await writeFile(file, JSON.stringify([source]));
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "github/example/project",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = () =>
      prepareLocalExternalImport(file, options, dependencies);
    const read = () => listLocalExternalFindings(options, dependencies);

    const prepared = await prepare();
    expect(prepared.preview.excluded).toEqual([]);
    expect(await read()).toEqual([]);
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await read();
    expect(stored).toHaveLength(1);
    const initial = stored[0]!;
    expect(initial).toMatchObject({
      repository: fixture.repository,
      provider: "github",
      sourceKey: options.sourceKey,
      assessment: { state: "not_assessed" },
      version: 1,
      evidence: { source_data: source },
    });
    if (kind !== "code-scanning") {
      expect(initial.evidence.locations).toEqual([]);
      expect(initial.evidence.packages?.[0]).toMatchObject({
        installed_version: null,
        manifest_path: null,
      });
    }
    if (kind === "global-advisory")
      expect(initial.evidence.details).not.toHaveProperty("repository");
    expect(initial.evidence).not.toHaveProperty("confidence");
    expect(initial.evidence).not.toHaveProperty("assessment");

    expect((await (await prepare()).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 1,
    });
    expect(await read()).toEqual(stored);

    if (source.source === "github-code-scanning") {
      source.alert.most_recent_instance.state = "fixed";
      source.alert.most_recent_instance.commit_sha = "b".repeat(40);
      delete source.alert.rule.security_severity_level;
    } else {
      source.advisory.withdrawn_at = "2026-01-03T00:00:00Z";
      source.advisory.severity = null;
    }
    await writeFile(file, JSON.stringify([source]));
    expect((await (await prepare()).import()).counts).toEqual({
      created: 0,
      updated: 1,
      unchanged: 0,
    });
    const updated = await read();
    expect(updated).toHaveLength(1);
    expect(updated[0]).toMatchObject({
      id: initial.id,
      sourceFindingId: initial.sourceFindingId,
      createdAt: initial.createdAt,
      version: 2,
      assessment: { state: "not_assessed" },
      evidence: {
        severity: "unknown",
        source_data: source,
        details: {
          source_status: kind === "code-scanning" ? "fixed" : "withdrawn",
        },
      },
    });
  },
);

test("native Dependabot JSONL preserves distinct package occurrences and updates provider state without assessing them", async () => {
  const fixture = await localFindingsFixture({
    remote: "https://github.com/example/project",
  });
  fixtures.push(fixture);
  const file = join(fixture.root, "selected.jsonl");
  const options = {
    repository: fixture.repository,
    provider: "github" as const,
    sourceKey: "github.com/example/project/dependabot",
  };
  const dependencies = { environment: fixture.environment };
  const first = dependabotAlert();
  const second = dependabotAlert(18);
  second.dependency.manifest_path = "services/web/package-lock.json";
  const malware = dependabotAlert(19);
  malware.security_advisory.classification = "malware";
  const write = () =>
    writeFile(
      file,
      [first, second, malware].map((alert) => JSON.stringify(alert)).join("\n"),
    );
  const prepare = () => prepareLocalExternalImport(file, options, dependencies);
  await write();
  const prepared = await prepare();
  expect(prepared.preview.excluded).toMatchObject([
    { position: 3, reason: expect.stringContaining("malware") },
  ]);
  expect(
    prepared.preview.findings.map((finding) => finding.source_finding_id),
  ).toEqual([
    "github.com/example/project/dependabot/17",
    "github.com/example/project/dependabot/18",
  ]);
  expect(prepared.preview.findings[0]!.evidence).toMatchObject({
    advisory_ids: [
      first.security_advisory.ghsa_id,
      first.security_advisory.cve_id,
    ],
    packages: [
      {
        name: "example-parser",
        ecosystem: "npm",
        installed_version: null,
        manifest_path: first.dependency.manifest_path,
        vulnerable_version_range:
          first.security_vulnerability.vulnerable_version_range,
        fixed_versions: ["1.2.3"],
      },
    ],
    code_revision: null,
    source_data: first,
  });
  expect((await prepared.import()).counts.created).toBe(2);
  first.state = "dismissed";
  await write();
  expect((await (await prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 1,
  });
  const stored = await listLocalExternalFindings(options, dependencies);
  expect(
    stored.find((row) => row.sourceFindingId.endsWith("/17")),
  ).toMatchObject({
    assessment: { state: "not_assessed" },
    evidence: { source_data: first },
  });
});

test.each(["code-scanning", "repository-advisory", "dependabot"] as const)(
  "GitHub %s refuses to attach another repository's evidence locally",
  async (kind) => {
    const fixture = await localFindingsFixture({
      remote: "https://github.com/example/other",
    });
    fixtures.push(fixture);
    const file = join(fixture.root, "github.json");
    await writeFile(
      file,
      JSON.stringify([
        kind === "dependabot" ? dependabotAlert() : githubSource(kind),
      ]),
    );
    await expect(
      prepareLocalExternalImport(
        file,
        {
          repository: fixture.repository,
          provider: "github",
          sourceKey: "github/example/project",
        },
        { environment: fixture.environment },
      ),
    ).rejects.toThrow(/repository/iu);
    expect(
      await listLocalExternalFindings(
        { repository: fixture.repository },
        { environment: fixture.environment },
      ),
    ).toEqual([]);
  },
);

test.each(["code-scanning", "repository-advisory"] as const)(
  "GitHub %s matches custom Enterprise repository names without changing source evidence",
  async (kind) => {
    const fixture = await localFindingsFixture({
      remote: "git@git.example.test:example/project.git",
    });
    fixtures.push(fixture);
    const source =
      kind === "code-scanning"
        ? importedAlert("refs/heads/main", "git.example.test")
        : importedAdvisory();
    source.repository = "Example/Project";
    if (source.source === "github-security-advisory") {
      source.githubHost = "git.example.test";
      source.url = source.url.replace("github.com", "git.example.test");
      source.advisory.html_url = source.url;
    }
    const file = join(fixture.root, "github-enterprise.json");
    await writeFile(file, JSON.stringify([source]));
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "github/example/project",
    };
    const dependencies = { environment: fixture.environment };
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview.excluded).toEqual([]);
    expect(
      prepared.preview.findings[0]!.evidence.details!.repository,
    ).toMatchObject({
      url: "https://git.example.test/Example/Project",
      name: "Example/Project",
    });
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await listLocalExternalFindings(options, dependencies);
    expect(stored[0]!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
    expect(stored[0]!.evidence.source_data).toEqual({ ...source });
  },
);
