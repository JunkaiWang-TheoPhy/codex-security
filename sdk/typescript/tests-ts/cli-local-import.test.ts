import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  dependencies as cliDependencies,
  FakeSignals,
} from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { opengrepJson } from "./support/opengrep-import-fixtures.js";
import {
  inspectorReport,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

const dependencies: typeof cliDependencies = (options = {}) => {
  const result = cliDependencies(options);
  return {
    ...result,
    environment: {
      ...result.environment,
      CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
    },
  };
};

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "local-import-cli-")),
  );
  roots.push(root);
  const repository = join(root, "example project");
  await mkdir(repository);
  execFileSync("git", ["init", "--quiet", repository]);
  execFileSync("git", [
    "-C",
    repository,
    "remote",
    "add",
    "origin",
    "https://github.com/example/project.git",
  ]);
  const file = join(root, "selected.json");
  const record = {
    id: "vendor-finding-1",
    name: "CVE-2026-0001",
    detailedName: "example-package",
    vendorSeverity: "HIGH",
    version: "1.2.3",
    fixedVersion: "1.2.4",
    locationPath: "/package-lock.json",
    vulnerableAsset: {
      id: "repository-branch-1",
      nativeType: "github#repositoryBranch",
      name: "example/project/main",
      cloudProviderURL: "https://github.com/example/project/tree/main",
    },
  };
  await writeFile(file, JSON.stringify([record]));
  const state = join(root, "state");
  const deps = {
    ...dependencies({
      currentDirectory: root,
      environment: {
        ...process.env,
        HOME: join(root, "home"),
        USERPROFILE: join(root, "home"),
        CODEX_HOME: join(root, "codex"),
        CODEX_SECURITY_STATE_DIR: state,
        CODEX_SECURITY_CLOUD_BASE_URL: "invalid-cloud-url",
      },
      onConfig: () => {
        throw new Error("Local imports must not initialize a model client");
      },
      onCodex: () => {
        throw new Error("Local imports must not invoke Codex or sign in");
      },
    }),
    cloudFetch: async () => {
      throw new Error("Local imports must not call Cloud");
    },
  };
  const command = [
    "publish",
    "findings",
    "selected.json",
    "--to",
    "local",
    "--repository",
    "example project",
    "--provider",
    "wiz",
    "--source-key",
    "tenant-example/vulnerability-finding",
    "--format",
    "json",
  ];
  return { root, repository, file, record, state, deps, command };
}

test("local preview and declined confirmation do not create database state or use Cloud", async () => {
  const f = await fixture();
  const preview = createCliTest(main);
  expect(await preview.runCli([...f.command, "--dry-run"], f.deps)).toBe(0);
  expect(preview.stderr.text()).toBe("");
  expect(JSON.parse(preview.stdout.text())).toMatchObject({
    dryRun: true,
    repository: f.repository,
    source: {
      provider: "wiz",
      source_key: "tenant-example/vulnerability-finding",
    },
    read: 1,
    findings: [
      { source_finding_id: f.record.id, evidence: { source_data: f.record } },
    ],
  });
  const declined = createCliTest(main);
  expect(
    await declined.runCli(f.command, {
      ...f.deps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async (question, defaultValue) => {
          expect(question).toContain("Store these 1 findings locally");
          expect(defaultValue).toBe(false);
          expect(declined.stderr.text()).toContain(f.repository);
          expect(declined.stderr.text()).toContain(f.record.id);
          expect(declined.stderr.text()).toContain("not assessed by Codex");
          return false;
        },
      },
    }),
  ).toBe(0);
  expect(JSON.parse(declined.stdout.text()).imported).toBe(false);
  const headless = createCliTest(main);
  expect(await headless.runCli(f.command, f.deps)).toBe(2);
  expect(headless.stderr.text()).toContain("needs confirmation");
  expect(await readdir(f.state).catch(() => [])).toEqual([]);
});

test("CLI imports a vendor report, reads local evidence, and updates the same source record", async () => {
  const f = await fixture();
  const first = createCliTest(main);
  expect(await first.runCli([...f.command, "--yes"], f.deps)).toBe(0);
  const imported = JSON.parse(first.stdout.text());
  expect(imported.counts).toEqual({ created: 1, updated: 0, unchanged: 0 });
  expect(imported.findings[0]).toMatchObject({
    repository: f.repository,
    provider: "wiz",
    sourceFindingId: f.record.id,
    version: 1,
    assessment: { state: "not_assessed" },
    evidence: { severity: "high", source_data: f.record },
  });
  const repeated = createCliTest(main);
  expect(await repeated.runCli([...f.command, "--yes"], f.deps)).toBe(0);
  expect(JSON.parse(repeated.stdout.text()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
  await writeFile(
    f.file,
    JSON.stringify([{ ...f.record, vendorSeverity: "CRITICAL" }]),
  );
  const updated = createCliTest(main);
  expect(await updated.runCli([...f.command, "--yes"], f.deps)).toBe(0);
  expect(JSON.parse(updated.stdout.text()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  const readback = createCliTest(main);
  expect(
    await readback.runCli(["findings", "imported", "--format", "json"], {
      ...f.deps,
      currentDirectory: () => f.repository,
    }),
  ).toBe(0);
  const result = JSON.parse(readback.stdout.text());
  expect(result.repository).toBe(f.repository);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({
    id: imported.findings[0].id,
    version: 2,
    assessment: { state: "not_assessed" },
    evidence: { severity: "critical" },
  });
  expect(result.findings[0].evidence.code_revision).toBeNull();
  expect(result.findings[0].evidence.confidence).toBeUndefined();
});

test("Inspector CLI uses an operator map for a repository with a name and project ARN", async () => {
  const f = await fixture();
  const report = inspectorReport();
  const resource = report.findings[0]!.resources[0]!;
  resource.details.codeRepository.projectName = "example/project";
  await writeFile(f.file, JSON.stringify(report));
  const mapping = JSON.stringify({ [resource.id]: inspectorRepositoryUrl });
  const map = join(f.root, "projects.json");
  await writeFile(map, mapping);
  const command = (mapPath: string) => [
    ...f.command.map((value) => (value === "wiz" ? "inspector" : value)),
    "--source-repository-url",
    inspectorRepositoryUrl,
    "--inspector-project-map",
    mapPath,
    "--dry-run",
  ];
  const run = async (path: string) => {
    const cli = createCliTest(main);
    const code = await cli.runCli(command(path), f.deps);
    return { code, stdout: cli.stdout.text(), stderr: cli.stderr.text() };
  };
  const preview = await run("projects.json");
  expect(preview.code).toBe(0);
  expect(JSON.parse(preview.stdout)).toMatchObject({
    findings: [{ source_finding_id: report.findings[0]!.findingArn }],
    dryRun: true,
  });

  if (process.platform === "linux") {
    const output = execFileSync(
      "sh",
      [
        "-c",
        'cat | exec "$@"',
        "sh",
        process.execPath,
        fileURLToPath(new URL("../src/cli.ts", import.meta.url)),
        ...command(map).map((value) =>
          value === "selected.json" ? "/dev/stdin" : value,
        ),
      ],
      { cwd: f.root, env: f.deps.environment, input: JSON.stringify(report) },
    );
    expect(JSON.parse(output.toString()).findings).toHaveLength(1);
  }

  const checkoutMap = join(f.repository, "projects.json");
  await writeFile(checkoutMap, mapping);
  const alias = join(f.root, "linked-checkout");
  await symlink(f.repository, alias, "junction");
  for (const path of [checkoutMap, join(alias, "projects.json")]) {
    const rejected = await run(path);
    expect(rejected.code).not.toBe(0);
    expect(rejected.stderr).toContain("outside the selected repository");
  }
  // A plain source directory can still own a link between two outside paths.
  await rm(join(f.repository, ".git"), { recursive: true });
  const config = join(f.root, "config");
  execFileSync("git", ["init", "--quiet", config]);
  await writeFile(join(config, "projects.json"), mapping);
  const bridge = join(f.repository, "maps");
  await symlink(config, bridge, "junction");
  const view = join(f.root, "config-view");
  await symlink(bridge, view, "junction");
  expect((await run(join(config, "projects.json"))).code).toBe(0);
  expect((await run(join(view, "projects.json"))).stderr).toContain(
    "outside the selected repository",
  );
  for (const contents of [
    Buffer.of(0xff),
    "[]",
    "{}",
    '{"invalid":"https://example.test/o/r"}',
  ]) {
    await writeFile(map, contents);
    const rejected = await run(map);
    expect(rejected.code).not.toBe(0);
    expect(rejected.stderr).toMatch(/inspector-project-map|project ARN/i);
  }
});

test("Cloud permits a trusted configuration checkout and rejects maps controlled by the report checkout", async () => {
  const f = await fixture();
  const report = inspectorReport();
  const resource = report.findings[0]!.resources[0]!;
  resource.details.codeRepository.projectName = "example/project";
  const reportInSource = join(f.repository, "report.json");
  await writeFile(reportInSource, JSON.stringify(report));
  await writeFile(f.file, JSON.stringify(report));
  const mapping = JSON.stringify({ [resource.id]: inspectorRepositoryUrl });
  const config = join(f.root, "config");
  execFileSync("git", ["init", "--quiet", config]);
  for (const directory of [f.root, f.repository, config])
    await writeFile(join(directory, "projects.json"), mapping);
  // This external alias enters the checkout and follows a second link back out.
  const bridge = join(f.repository, "maps");
  await symlink(f.root, bridge, "junction");
  const alias = join(f.root, "alias");
  await symlink(bridge, alias, "junction");
  const run = async (
    directory: string,
    cwd = f.repository,
    reportFile = reportInSource,
  ) => {
    const cli = createCliTest(main);
    await cli.runCli(
      [
        "publish",
        "findings",
        reportFile,
        "--provider",
        "inspector",
        "--to",
        "cloud",
        "--repository",
        inspectorRepositoryUrl,
        "--source-repository-url",
        inspectorRepositoryUrl,
        "--source-key",
        "inspector/example/project",
        "--inspector-project-map",
        join(directory, "projects.json"),
        "--dry-run",
      ],
      { ...f.deps, currentDirectory: () => cwd },
    );
    return cli.stderr.text();
  };
  if (process.platform !== "win32") {
    const external = join(f.root, "external");
    await mkdir(external);
    await writeFile(join(external, "projects.json"), mapping);
    const repeated = join(f.root, "repeated-separators");
    await symlink(`${bridge}//external`, repeated);
    expect(await run(repeated)).toContain("outside the selected repository");

    const hop = join(external, "hop");
    await symlink(config, hop);
    const exported = join(external, "linked-report.json");
    await symlink("hop/../example project/report.json", exported);
    expect(await run(f.repository, f.root, exported)).toContain(
      "outside the selected repository",
    );
    expect(await run(f.root, f.root, exported)).toContain(
      "CODEX_SECURITY_CLOUD_BASE_URL",
    );

    const replacement = join(f.root, "\uFFFD");
    const validAlias = join(f.root, "valid-alias");
    await symlink(f.root, replacement);
    await symlink(replacement, validAlias);
    expect(await run(validAlias)).toContain("CODEX_SECURITY_CLOUD_BASE_URL");
  }
  if (process.platform === "linux") {
    // The kernel traverses this checkout even though the target cannot round-trip through UTF-8.
    const rawName = Buffer.concat([Buffer.from(f.root + "/"), Buffer.of(0xff)]);
    await symlink(f.repository, rawName);
    const rawAlias = join(f.root, "byte-alias");
    await symlink(Buffer.concat([rawName, Buffer.from("/maps")]), rawAlias);
    expect(await run(rawAlias)).toContain("UTF-8 symlink targets");
  }
  expect(await run(config)).toContain("CODEX_SECURITY_CLOUD_BASE_URL");
  expect(await run(config, config, f.file)).toContain(
    "CODEX_SECURITY_CLOUD_BASE_URL",
  );
  for (const directory of [f.repository, alias])
    expect(await run(directory)).toContain("outside the selected repository");
  // The report path enters the checkout and follows its "maps" link back out.
  expect(
    await run(f.repository, f.root, join(alias, "selected.json")),
  ).toContain("outside the selected repository");
  if (process.platform === "win32") {
    const linkedConfig = join(f.root, "linked-config");
    try {
      await symlink("missing\\..\\config", linkedConfig, "dir");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    expect(await realpath(linkedConfig)).toBe(await realpath(config));
    expect(await run(linkedConfig)).toContain("CODEX_SECURITY_CLOUD_BASE_URL");
  }
});

test("the Inspector map option cannot be used for other providers", async () => {
  const f = await fixture();
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      [...f.command, "--inspector-project-map", "unused.json", "--dry-run"],
      f.deps,
    ),
  ).not.toBe(0);
  expect(cli.stderr.text()).toContain("requires --provider inspector");
});

test("CLI imports OpenGrep evidence locally without assessing it", async () => {
  const f = await fixture();
  const report = opengrepJson();
  await writeFile(f.file, JSON.stringify(report));
  const sourceRepositoryUrl = "https://github.com/example/project";
  const imported = createCliTest(main);
  expect(
    await imported.runCli(
      [
        "publish",
        "findings",
        "selected.json",
        "--to",
        "local",
        "--repository",
        "example project",
        "--provider",
        "opengrep",
        "--source-repository-url",
        sourceRepositoryUrl,
        "--source-key",
        "example/opengrep",
        "--yes",
        "--format",
        "json",
      ],
      f.deps,
    ),
  ).toBe(0);
  const result = JSON.parse(imported.stdout.text());
  expect(result.report.errors).toEqual(report.errors);
  expect(result.counts).toEqual({
    created: 1,
    updated: 0,
    unchanged: 0,
  });
  const readback = createCliTest(main);
  expect(
    await readback.runCli(
      ["findings", "imported", "example project", "--format", "json"],
      f.deps,
    ),
  ).toBe(0);
  const findings = JSON.parse(readback.stdout.text()).findings;
  expect(findings).toHaveLength(1);
  expect(findings[0]).toMatchObject({
    provider: "semgrep",
    assessment: { state: "not_assessed" },
    evidence: {
      severity: "unknown",
      details: {
        scanner_origin: "OpenGrep",
        repository: { url: sourceRepositoryUrl },
      },
      source_data: {
        report: {
          version: report.version,
        },
        scan_error_count: report.errors.length,
        results: report.results,
      },
    },
  });
});

test("local import confirms exclusions and returns partial status after storing ready records", async () => {
  const f = await fixture();
  await writeFile(
    f.file,
    JSON.stringify([
      f.record,
      { ...f.record, id: "unsupported", vendorSeverity: "not-a-severity" },
    ]),
  );
  const cli = createCliTest(main);
  expect(
    await cli.runCli(f.command, {
      ...f.deps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async (question) => {
          expect(question).toContain("skip 1 excluded records");
          expect(cli.stderr.text()).toContain("Excluded: 1");
          return true;
        },
      },
    }),
  ).toBe(1);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    read: 2,
    ready: 1,
    counts: { created: 1 },
  });
});

test.each(["SIGINT", "SIGTERM"] as const)(
  "local import forwards %s cancellation without storing findings",
  async (signalName) => {
    const signals = new FakeSignals();
    const deps = dependencies({
      signals,
      currentDirectory: resolve("workspace"),
    });
    const cli = createCliTest(main);
    let imports = 0;
    deps.prepareLocalExternalImport = async (file, options, settings) => {
      expect(file).toBe(resolve("workspace", "selected.json"));
      expect(options.repository).toBe(resolve("workspace", "project"));
      expect(settings?.environment).toBe(deps.environment);
      signals.emit(signalName);
      settings?.signal?.throwIfAborted();
      imports += 1;
      throw new Error("Import should have been canceled");
    };
    expect(
      await cli.runCli(
        [
          "publish",
          "findings",
          "selected.json",
          "--to",
          "local",
          "--repository",
          "project",
          "--provider",
          "wiz",
          "--source-key",
          "tenant-example/findings",
          "--yes",
          "--format",
          "json",
        ],
        deps,
      ),
    ).toBe(signalName === "SIGINT" ? 130 : 143);
    expect(imports).toBe(0);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  },
);

test("imported readback resolves its repository argument and supports structured output", async () => {
  const deps = dependencies({ currentDirectory: resolve("workspace") });
  deps.listLocalExternalFindings = async ({ repository }, settings) => {
    expect(repository).toBe(resolve("workspace", "project"));
    expect(settings?.environment).toBe(deps.environment);
    expect(settings?.signal?.aborted).toBe(false);
    return [];
  };
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      ["findings", "imported", "project", "--format", "json"],
      deps,
    ),
  ).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toEqual({
    repository: resolve("workspace", "project"),
    findings: [],
  });
});

for (const format of ["json", "jsonl"] as const) {
  test.each(["SIGINT", "SIGTERM"] as const)(
    `imported readback reports %s cancellation in ${format} full output`,
    async (signalName) => {
      const signals = new FakeSignals();
      const deps = dependencies({
        signals,
        currentDirectory: resolve("workspace"),
      });
      deps.listLocalExternalFindings = async (_selection, settings) => {
        expect(settings?.signal).toBeDefined();
        signals.emit(signalName);
        settings!.signal!.throwIfAborted();
        throw new Error("Readback should have been canceled");
      };
      const cli = createCliTest(main);
      expect(
        await cli.runCli(
          ["findings", "imported", "--format", format, "--full-output"],
          deps,
        ),
      ).toBe(signalName === "SIGINT" ? 130 : 143);
      expect(JSON.parse(cli.stdout.text())).toMatchObject({
        ok: false,
        error: { code: "FINDINGS_READ_FAILED", message: signalName },
      });
      expect(cli.stderr.text()).toBe("");
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    },
  );
}

test("finding import requires an explicit destination and advertises local repository paths", async () => {
  const cli = createCliTest(main);
  expect(
    await cli.runCli(["publish", "findings", "--help"], dependencies()),
  ).toBe(0);
  expect(cli.stdout.text()).toContain("local");
  expect(cli.stdout.text()).toContain("Local repository path");
  const missing = createCliTest(main);
  expect(
    await missing.runCli(
      [
        "publish",
        "findings",
        "selected.json",
        "--repository",
        "project",
        "--provider",
        "wiz",
        "--source-key",
        "tenant-example/findings",
        "--dry-run",
      ],
      dependencies(),
    ),
  ).not.toBe(0);
  expect(missing.stderr.text()).toContain("to");
});
