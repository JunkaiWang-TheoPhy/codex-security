import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { trivyReport } from "./support/trivy-import-fixtures.js";

const checkoutUrl = "https://github.com/example/project";
const foreignUrl = "https://github.com/example/other";
const mismatch = "does not match a configured remote";

test.each([
  ["foreign empty report", {}, foreignUrl, mismatch],
  [
    "foreign excluded-only report",
    { Results: [{ Class: "os-pkgs" }] },
    foreignUrl,
    mismatch,
  ],
  [
    "foreign artifact URL only",
    { Metadata: {}, ArtifactName: foreignUrl },
    checkoutUrl,
    mismatch,
  ],
  [
    "conflicting report claims",
    { ArtifactName: foreignUrl },
    "file:///synthetic/mirror",
    "identify different repositories",
  ],
  [
    "matching SSH alias",
    {
      Metadata: { RepoURL: "ssh://git@ssh.github.com:443/example/project.git" },
      Results: [{ Class: "os-pkgs" }],
    },
    checkoutUrl,
    null,
  ],
  ["no report remote", { Metadata: {} }, foreignUrl, null],
  ["no comparable checkout remote", {}, "file:///synthetic/mirror", null],
] as const)(
  "Trivy checks report provenance without accepted findings: %s",
  async (_name, overrides, remote, error) => {
    const fixture = await localFindingsFixture({ remote });
    try {
      const file = join(fixture.root, "trivy.json");
      const report = { ...trivyReport(), Results: [], ...overrides };
      await writeFile(file, JSON.stringify(report));
      const prepared = prepareLocalExternalImport(
        file,
        {
          repository: fixture.repository,
          provider: "trivy",
          trivyScanRoot: ".",
          sourceKey: "example/project/main",
        },
        { environment: fixture.environment },
      );
      if (error) await expect(prepared).rejects.toThrow(error);
      else {
        const { preview } = await prepared;
        expect(preview.findings).toEqual([]);
        expect(preview.excluded).toHaveLength(report.Results.length);
      }
    } finally {
      await fixture.dispose();
    }
  },
);

test("Trivy import preserves the occurrence across revisions without assessing it", async () => {
  const fixture = await localFindingsFixture({
    remote: "git@github.com:example/project.git",
  });
  try {
    const file = join(fixture.root, "trivy.json");
    const report = trivyReport();
    const options = {
      repository: fixture.repository,
      provider: "trivy" as const,
      trivyScanRoot: ".",
      sourceKey: "example/project/main",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = () =>
      prepareLocalExternalImport(file, options, dependencies);
    await writeFile(file, JSON.stringify(report));
    const preview = await prepare();
    expect(preview.preview.excluded).toEqual([]);
    expect(await listLocalExternalFindings(options, dependencies)).toEqual([]);
    expect((await preview.import()).counts.created).toBe(1);
    expect((await (await prepare()).import()).counts.unchanged).toBe(1);

    const updatedCommit = "b".repeat(40);
    await writeFile(
      file,
      JSON.stringify({
        ...report,
        Metadata: { ...report.Metadata, Commit: updatedCommit },
      }),
    );
    expect((await (await prepare()).import()).counts).toEqual({
      created: 0,
      updated: 1,
      unchanged: 0,
    });
    const stored = await listLocalExternalFindings(options, dependencies);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({
      provider: "trivy",
      sourceFindingId: preview.preview.findings[0]!.source_finding_id,
      version: 2,
      evidence: { code_revision: updatedCommit },
      assessment: { state: "not_assessed" },
    });
  } finally {
    await fixture.dispose();
  }
});

test.each([
  ["https://github.com/example/project", "https://github.com/example/other"],
  ["tenant-a@git.example.test:project", "tenant-b@git.example.test:project"],
  ["alice@git.example.test:project.git", "alice@git.example.test:project"],
  [
    "git@github.com:example/project.git",
    "ssh://git@github.com/example/project?",
  ],
])(
  "Trivy source %s cannot be attached to checkout %s",
  async (source, checkout) => {
    const fixture = await localFindingsFixture({
      remote: checkout,
    });
    try {
      const file = join(fixture.root, "trivy.json");
      const report = trivyReport();
      report.Metadata.RepoURL = source;
      await writeFile(file, JSON.stringify(report));
      await expect(
        prepareLocalExternalImport(
          file,
          {
            repository: fixture.repository,
            provider: "trivy",
            trivyScanRoot: ".",
            sourceKey: "example/project/main",
          },
          {
            environment: fixture.environment,
            sourceRepositories: [{ url: source, platform: "github" }],
          },
        ),
      ).rejects.toThrow("does not match a configured remote");
    } finally {
      await fixture.dispose();
    }
  },
);
