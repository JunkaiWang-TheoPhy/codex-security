import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

test("Inspector replays, suppression and an empty export preserve unassessed repository history", async () => {
  const fixture = await localFindingsFixture({
    remote: inspectorRepositoryUrl,
  });
  try {
    const path = join(fixture.root, "inspector.json.gz");
    const options = {
      provider: "inspector" as const,
      sourceRepositoryUrl: inspectorRepositoryUrl,
      repository: fixture.repository,
      sourceKey: "inspector/example/project",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = async (findings: unknown[]) => {
      await writeFile(path, gzipSync(JSON.stringify({ findings })));
      return prepareLocalExternalImport(path, options, dependencies);
    };
    const input = inspectorPackageFinding();
    const original = await prepare([input]);
    expect((await original.import()).counts.created).toBe(1);
    expect((await (await prepare([input])).import()).counts.unchanged).toBe(1);
    expect(
      (await (await prepare([{ ...input, status: "SUPPRESSED" }])).import())
        .counts.updated,
    ).toBe(1);
    expect((await (await prepare([])).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 0,
    });
    const records = await listLocalExternalFindings(options, dependencies);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      provider: "inspector",
      sourceFindingId: input.findingArn,
      version: 2,
      assessment: { state: "not_assessed" },
    });
    await expect(
      prepareLocalExternalImport(
        path,
        { ...options, sourceRepositoryUrl: "https://github.com/example/other" },
        dependencies,
      ),
    ).rejects.toThrow(/repository|remote/i);
    const altered = structuredClone(original.preview);
    altered.findings[0]!.evidence.details!.repository!.url =
      "https://github.com/example/other";
    await expect(
      prepareNormalizedLocalImport(altered, options, dependencies),
    ).rejects.toThrow(/retained scanner repository/i);
    const wrongArn = structuredClone(original.preview);
    wrongArn.findings[0]!.source_finding_id = input.findingArn.replace(
      /a$/u,
      "b",
    );
    await expect(
      prepareNormalizedLocalImport(wrongArn, options, dependencies),
    ).rejects.toThrow(/ARN|identity|source finding/i);
  } finally {
    await fixture.dispose();
  }
});
