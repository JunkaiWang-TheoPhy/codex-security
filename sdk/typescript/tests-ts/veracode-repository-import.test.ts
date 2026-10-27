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
  veracodePolicyPage,
  veracodePolicyRow,
} from "./support/veracode-import-fixtures.js";

test("replaying a Veracode policy flaw tracks evidence without assessing another build or repository", async () => {
  const url = "https://github.com/example/project";
  const fixture = await localFindingsFixture({ remote: url });
  try {
    const path = join(fixture.root, "veracode.json.gz");
    const options = {
      provider: "veracode" as const,
      repository: fixture.repository,
      sourceRepositoryUrl: url,
      sourceKey: "veracode/example/static",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = async (rows: ReturnType<typeof veracodePolicyRow>[]) => {
      await writeFile(path, gzipSync(JSON.stringify(veracodePolicyPage(rows))));
      return prepareLocalExternalImport(path, options, dependencies);
    };
    const row = veracodePolicyRow(1);
    const first = await prepare([row, veracodePolicyRow(2)]);
    expect((await first.import()).counts.created).toBe(2);
    expect((await (await prepare([row])).import()).counts.unchanged).toBe(1);
    expect(
      (
        await (
          await prepare([
            {
              ...row,
              build_id: 13,
              finding_status: { ...row.finding_status, status: "CLOSED" },
            },
          ])
        ).import()
      ).counts.updated,
    ).toBe(1);
    expect((await (await prepare([])).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 0,
    });
    const records = await listLocalExternalFindings(options, dependencies);
    expect(records.map(({ version }) => version).sort()).toEqual([1, 2]);
    expect(
      records.every(({ assessment }) => assessment.state === "not_assessed"),
    ).toBe(true);
    await expect(
      prepareLocalExternalImport(
        path,
        { ...options, sourceRepositoryUrl: "https://github.com/example/other" },
        dependencies,
      ),
    ).rejects.toThrow(/remote|repository/i);
    const wrong = structuredClone(first.preview);
    wrong.findings[0]!.evidence.details!.repository!.url =
      "https://github.com/example/other";
    await expect(
      prepareNormalizedLocalImport(wrong, options, dependencies),
    ).rejects.toThrow(/retained scanner repository/i);
    const relabeled = structuredClone(first.preview);
    relabeled.findings.splice(1);
    relabeled.findings[0]!.source_finding_id =
      first.preview.findings[1]!.source_finding_id;
    await expect(
      prepareNormalizedLocalImport(relabeled, options, dependencies),
    ).rejects.toThrow(/source finding ID|occurrence/i);
  } finally {
    await fixture.dispose();
  }
});
