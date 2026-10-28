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
import { normalizeInspectorFindings } from "../src/inspector-findings.js";
import {
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

test("matching native Enterprise GitHub URLs bind to case-varied SSH remotes", async () => {
  const url = "https://git.example.test/example/project";
  const fixture = await localFindingsFixture({
    remote: "git@git.example.test:EXAMPLE/Project.git",
  });
  try {
    const input = inspectorPackageFinding();
    input.resources[0]!.details.codeRepository.projectName =
      "https://git.example.test/Example/Project";
    const path = join(fixture.root, "enterprise.json");
    await writeFile(path, JSON.stringify({ findings: [input] }));
    const options = {
      provider: "inspector" as const,
      sourceRepositoryUrl: url,
      sourceKey: "inspector/enterprise/project",
      repository: fixture.repository,
    };
    const dependencies = { environment: fixture.environment };
    const prepared = await prepareLocalExternalImport(
      path,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toHaveLength(1);
    prepared.preview.findings[0]!.evidence.details = {
      ...prepared.preview.findings[0]!.evidence.details!,
      repository: { url: "https://git.example.test/Example/Project" },
    };
    expect(
      (
        await (
          await prepareNormalizedLocalImport(
            prepared.preview,
            options,
            dependencies,
          )
        ).import()
      ).counts.created,
    ).toBe(1);
  } finally {
    await fixture.dispose();
  }
});

const sshProject = "ssh://git@github.com/example/project";
const homeProject = "github.com/~/example/project?other";
const scpProject = "github.com:example/project#other";
const repositoryBindings: [string, string, string?][] = [
  [`${inspectorRepositoryUrl}?repo=other`, inspectorRepositoryUrl],
  [`${inspectorRepositoryUrl}?`, inspectorRepositoryUrl],
  [`${inspectorRepositoryUrl}#`, inspectorRepositoryUrl],
  [`${sshProject}?other`, `${sshProject}?Other`],
  [`ssh://alice@${homeProject}`, `ssh://bob@${homeProject}`],
  [`alice@${scpProject}`, `bob@${scpProject}`],
  [
    "ssh://alice@git.example.test/~/project",
    "ssh://bob@git.example.test/~/project",
  ],
  ["alice@git.example.test:team/project", "bob@git.example.test:team/project"],
  ["alice@host.test:D:/shared/project", "bob@host.test:D:/shared/project"],
  [
    "café@host.test:~/repo",
    "caf%C3%A9@host.test:~/repo",
    "ssh://caf%C3%A9@host.test/~/repo",
  ],
  [
    "DOMAIN\\alice@host.test:~/repo",
    "DOMAIN%5Calice@host.test:~/repo",
    "ssh://DOMAIN%5Calice@host.test/~/repo",
  ],
  [
    "ssh://team:one@host.test/~/repo",
    "ssh://team:two@host.test/~/repo",
    "ssh://team%3Aone@host.test/~/repo",
  ],
  [
    "ssh://u%00%23v@host.test/~/repo#x",
    "ssh://u@host.test/~/repo#v%00%23x",
    "ssh://u%2500%23v@host.test/~/repo#x",
  ],
  [
    "ssh://host.test/~/repo#blue",
    "ssh://alice@host.test/~/other#blue",
    "ssh://alice@host.test/~/repo#blue",
  ],
  [
    "ssh://alice@host.test/~/repo",
    "ssh://bob@host.test/~/repo",
    "ssh://host.test/~/repo",
  ],
  [
    "ssh://alice@host.test/./~/repo",
    "ssh://bob@host.test/./~/other",
    "ssh://bob@host.test/./~/repo",
  ],
  ["alice@host.test:/~/repo", "bob@host.test:/~/repo"],
  ["ssh://alice@host.test/~/../repo", "ssh://bob@host.test/~/../repo"],
  ["ssh://alice@host.test/%7E%2F../repo", "ssh://bob@host.test/%7E%2F../repo"],
  [`${sshProject}#blue`, `${sshProject}.git#blue`, `${sshProject}#blue.git`],
  ["git://github.com/example/project?other", inspectorRepositoryUrl],
];
test.each(
  repositoryBindings.map(
    ([remote, other, equivalent = remote.replace(/^ssh:/u, "git+ssh:")]) =>
      [remote, other, equivalent] as const,
  ),
)(
  "native and typed Inspector findings bind to the matching checkout: %s",
  async (remote, other, equivalent) => {
    const fixture = await localFindingsFixture({ remote });
    try {
      const data = normalizeInspectorFindings(
        { findings: [inspectorPackageFinding()] },
        inspectorRepositoryUrl,
        "local",
      );
      const options = {
        provider: "inspector" as const,
        sourceKey: "inspector/example/project",
        repository: fixture.repository,
      };
      const deps = { environment: fixture.environment };
      const native = data.findings[0]!;
      const typed = (url: string): typeof native => ({
        source_finding_id: "sdk-id",
        evidence: {
          title: "Imported alert",
          severity: "unknown",
          details: { kind: "sast", repository: { url } },
        },
      });
      const store = async (row: typeof native) =>
        (
          await prepareNormalizedLocalImport(
            { ...data, findings: [row] },
            options,
            deps,
          )
        ).import();
      for (const row of [native, typed(other)])
        await expect(store(row)).rejects.toThrow(
          "does not match a configured remote",
        );
      expect(await listLocalExternalFindings(options, deps)).toHaveLength(0);
      expect((await store(typed(equivalent))).counts.created).toBe(1);
    } finally {
      await fixture.dispose();
    }
  },
);

test("SQLite replay checks the Inspector project mapping independently of retained evidence", async () => {
  const otherUrl = "https://git.example.test/example/project";
  const fixture = await localFindingsFixture({
    remote: inspectorRepositoryUrl,
  });
  const other = await localFindingsFixture({ remote: otherUrl });
  try {
    const finding = inspectorPackageFinding();
    const project = finding.resources[0]!;
    project.details.codeRepository.projectName = "example/project";
    const path = join(fixture.root, "native.json");
    await writeFile(path, JSON.stringify({ findings: [finding] }));
    const options = {
      provider: "inspector" as const,
      repository: fixture.repository,
      sourceKey: "inspector/example/project",
      sourceRepositoryUrl: inspectorRepositoryUrl,
      inspectorProjectMap: new Map([[project.id, inspectorRepositoryUrl]]),
    };
    const deps = { environment: fixture.environment };
    const prepared = await prepareLocalExternalImport(path, options, deps);
    expect((await prepared.import()).counts.created).toBe(1);
    const saved = (await listLocalExternalFindings(options, deps))[0]!;
    const replay = {
      findings: [
        { source_finding_id: saved.sourceFindingId, evidence: saved.evidence },
      ],
      read: 1,
      excluded: [],
    };
    const same = await prepareNormalizedLocalImport(replay, options, deps);
    expect((await same.import()).counts.unchanged).toBe(1);

    // The forged source and the second checkout agree. Only the trusted project
    // mapping identifies the original host.
    saved.evidence.source_data!["sourceRepositoryUrl"] = otherUrl;
    await expect(
      prepareNormalizedLocalImport(
        replay,
        { ...options, repository: other.repository },
        { environment: other.environment },
      ),
    ).rejects.toThrow(/project|repository/i);
  } finally {
    await Promise.all([fixture.dispose(), other.dispose()]);
  }
});

test("an Inspector provider claim cannot loosen an operator's custom host mapping", async () => {
  const trusted = "https://scm.example.test/Team/Project";
  const other = "https://scm.example.test/team/project";
  const fixture = await localFindingsFixture({ remote: other });
  try {
    const input = inspectorPackageFinding();
    const project = input.resources[0]!;
    project.details.codeRepository.projectName = "team/project";
    const report = { findings: [input] };
    const map = new Map([[project.id, trusted]]);
    const options = {
      provider: "inspector" as const,
      sourceKey: "inspector/example/project",
      repository: fixture.repository,
      sourceRepositoryUrl: trusted,
      inspectorProjectMap: map as typeof map | undefined,
    };
    const deps = { environment: fixture.environment };
    expect(() =>
      normalizeInspectorFindings(report, other, "local", map),
    ).toThrow("mapping does not match");
    const prepared = normalizeInspectorFindings(report, trusted, "local", map);
    for (const readerUrl of [undefined, trusted, other]) {
      await expect(
        prepareNormalizedLocalImport(prepared, options, {
          ...deps,
          sourceRepositories: readerUrl
            ? [{ url: readerUrl, platform: "github" }]
            : [],
        }),
      ).rejects.toThrow("does not match");
    }
    project.details.codeRepository.projectName = trusted;
    const path = join(fixture.root, "mapped.json");
    await writeFile(path, JSON.stringify(report));
    const native = normalizeInspectorFindings(report, trusted, "local", map);
    for (const start of [
      () => prepareNormalizedLocalImport(native, options, deps),
      () => prepareLocalExternalImport(path, options, deps),
    ]) {
      options.inspectorProjectMap = new Map(map);
      const pending = start();
      options.inspectorProjectMap.clear();
      options.inspectorProjectMap = undefined;
      await expect(pending).rejects.toThrow(
        "does not match a configured remote",
      );
    }
    project.details.codeRepository.projectName = other;
    expect(() =>
      normalizeInspectorFindings(report, trusted, "local", map),
    ).toThrow("native repository does not match");
  } finally {
    await fixture.dispose();
  }
});

test("an omitted Inspector provider cannot erase a known platform or disguise conflicting providers", async () => {
  const url = "https://git.example.test/example/project";
  const fixture = await localFindingsFixture({
    remote: "git@git.example.test:EXAMPLE/Project.git",
  });
  try {
    const known = inspectorPackageFinding();
    const source = known.resources[0]!;
    source.details.codeRepository.projectName = url;
    const variant = (providerType?: string) => ({
      ...known,
      findingArn: known.findingArn.replace(/a$/u, "b"),
      resources: [
        {
          ...source,
          details: {
            codeRepository: {
              projectName: url,
              integrationArn: source.details.codeRepository.integrationArn,
              ...(providerType ? { providerType } : {}),
            },
          },
        },
      ],
    });
    const path = join(fixture.root, "native.json");
    const options = {
      provider: "inspector" as const,
      repository: fixture.repository,
      sourceRepositoryUrl: url,
      sourceKey: "inspector/project",
    };
    const deps = { environment: fixture.environment };
    for (const other of [variant(), variant("GITLAB_SELF_MANAGED")]) {
      for (const rows of [
        [known, other],
        [other, known],
      ]) {
        await writeFile(path, JSON.stringify({ findings: rows }));
        const file = () => prepareLocalExternalImport(path, options, deps);
        const records = rows.flatMap(
          (row) =>
            normalizeInspectorFindings({ findings: [row] }, url, "local")
              .findings,
        );
        const normalized = () =>
          prepareNormalizedLocalImport(
            { findings: records, read: 2, excluded: [] },
            options,
            deps,
          );
        if ("providerType" in other.resources[0]!.details.codeRepository) {
          await expect(file()).rejects.toThrow(/project|provider|integration/i);
          await expect(normalized()).rejects.toThrow(
            /project|provider|integration/i,
          );
        } else {
          expect((await file()).preview.findings).toHaveLength(2);
          expect((await normalized()).preview.findings).toHaveLength(2);
          const knownIndex = rows.indexOf(known);
          records[knownIndex]!.evidence.source_data!["sourceRepositoryUrl"] =
            "https://git.example.test/EXAMPLE/Project";
          expect((await normalized()).preview.findings).toHaveLength(2);
        }
      }
    }
  } finally {
    await fixture.dispose();
  }
});

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
    altered.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://github.com/example/other" },
    };
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

test("a normalized local selection cannot combine findings from different Inspector projects", async () => {
  const fixture = await localFindingsFixture();
  try {
    const upstream = inspectorPackageFinding();
    const fork = inspectorPackageFinding();
    fork.findingArn = fork.findingArn.replace(/a$/u, "b");
    fork.resources[0]!.id = fork.resources[0]!.id.replace(
      "22222222",
      "33333333",
    );
    fork.resources[0]!.details.codeRepository.projectName =
      "https://github.com/fork/project";
    const findings = [
      ...normalizeInspectorFindings(
        { findings: [upstream] },
        inspectorRepositoryUrl,
        "local",
      ).findings,
      ...normalizeInspectorFindings(
        { findings: [fork] },
        "https://github.com/fork/project",
        "local",
      ).findings,
    ];
    await expect(
      prepareNormalizedLocalImport(
        { read: 2, excluded: [], findings },
        {
          provider: "inspector",
          sourceKey: "inspector/project",
          repository: fixture.repository,
        },
        { environment: fixture.environment },
      ),
    ).rejects.toThrow("more than one repository project");
  } finally {
    await fixture.dispose();
  }
});

test("normalized imports bind native Inspector evidence and maps to their provider", async () => {
  const fixture = await localFindingsFixture({
    remote: inspectorRepositoryUrl,
  });
  try {
    const native = inspectorPackageFinding();
    const normalized = normalizeInspectorFindings(
      { findings: [native] },
      inspectorRepositoryUrl,
      "local",
    );
    const row = normalized.findings[0]!;
    const prepare = (
      finding: typeof row,
      provider: "inspector" | "wiz",
      inspectorProjectMap?: ReadonlyMap<string, string>,
    ) =>
      prepareNormalizedLocalImport(
        { ...normalized, findings: [finding] },
        {
          provider,
          sourceKey: "scanner/project",
          repository: fixture.repository,
          inspectorProjectMap,
        },
        { environment: fixture.environment },
      );
    const workload = {
      ...native,
      resources: [{ type: "AWS_EC2_INSTANCE", id: "i-example" }],
    };
    await expect(
      prepare(
        {
          source_finding_id: "CVE-2099-1234",
          evidence: { ...row.evidence, source_data: workload },
        },
        "inspector",
      ),
    ).rejects.toThrow("retained Inspector");

    const opaque = { ...row, evidence: { ...row.evidence, source_data: {} } };
    const map = new Map([[native.resources[0]!.id, inspectorRepositoryUrl]]);
    await expect(prepare(opaque, "wiz", map)).rejects.toThrow(
      "map requires the inspector provider",
    );
    // A source ID alone does not identify the provider of normalized evidence.
    const prepared = await prepare(opaque, "wiz");
    expect(prepared.preview.findings[0]!.source_finding_id).toBe(
      native.findingArn,
    );
  } finally {
    await fixture.dispose();
  }
});
