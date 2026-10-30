import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { normalizeBlackDuckFindings } from "../src/blackduck-findings.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  blackDuckBomReport,
  blackDuckBomRow,
} from "./support/blackduck-import-fixtures.js";

test("Black Duck keeps package occurrences unassessed across replay, mitigation, and missing rows", async () => {
  const sourceRepositoryUrl = "https://git.example.test/project.git";
  await using fixture = await localFindingsFixture({
    remote: sourceRepositoryUrl,
  });
  const path = join(fixture.root, "vulnerable-components.json.gz");
  const options = {
    provider: "blackduck" as const,
    sourceRepositoryUrl,
    repository: fixture.repository,
    sourceKey: "scanner/project-a/release-a",
  };
  const dependencies = { environment: fixture.environment };
  const prepare = async (input: unknown) => {
    await writeFile(path, gzipSync(JSON.stringify(input)));
    return prepareLocalExternalImport(path, options, dependencies);
  };
  const row = {
    ...blackDuckBomRow(),
    packageUrl: "pkg:golang/git.example.test/team/module/v2@v2.1.0",
  };
  const first = await prepare(blackDuckBomReport([row]));
  expect((await first.import()).counts.created).toBe(1);
  expect((await (await prepare([row])).import()).counts.unchanged).toBe(1);
  const mitigated = {
    ...row,
    vulnerabilityWithRemediation: {
      ...row.vulnerabilityWithRemediation,
      remediationStatus: "MITIGATED",
    },
  };
  expect(
    (await (await prepare(blackDuckBomReport([mitigated]))).import()).counts
      .updated,
  ).toBe(1);
  await expect(
    prepare({ ...blackDuckBomReport([row]), totalCount: 20 }),
  ).rejects.toThrow();
  expect(
    (await (await prepare(blackDuckBomReport([]))).import()).counts,
  ).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  const records = await listLocalExternalFindings(options, dependencies);
  expect(records).toHaveLength(1);
  expect(records[0]).toMatchObject({
    provider: "blackduck",
    sourceFindingId: first.preview.findings[0]!.source_finding_id,
    version: 2,
    evidence: {
      packages: [
        {
          name: "git.example.test/team/module/v2",
          ecosystem: "golang",
          installed_version: "v2.1.0",
        },
      ],
    },
    assessment: { state: "not_assessed" },
  });
  const mixed = structuredClone(first.preview);
  mixed.findings.push(
    ...normalizeBlackDuckFindings(
      [blackDuckBomRow(undefined, "release-b")],
      sourceRepositoryUrl,
      "local",
    ).findings,
  );
  await expect(
    prepareNormalizedLocalImport(mixed, options, dependencies),
  ).rejects.toThrow(/same project version/);
  const altered = structuredClone(first.preview);
  altered.findings[0]!.evidence.details = {
    kind: "sast",
    repository: { url: "https://github.com/example/other" },
  };
  await expect(
    prepareNormalizedLocalImport(altered, options, dependencies),
  ).rejects.toThrow(/retained scanner repository/i);
  const remote = sourceRepositoryUrl + "?repo=other";
  execFileSync("git", ["remote", "set-url", "origin", remote], {
    cwd: fixture.repository,
  });
  await expect(
    prepareNormalizedLocalImport(first.preview, options, dependencies),
  ).rejects.toThrow(/does not match a configured remote/);
});
