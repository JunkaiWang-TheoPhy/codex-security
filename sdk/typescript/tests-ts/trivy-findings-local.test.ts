import { expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import {
  listLocalExternalFindings,
  normalizeTrivyFindings,
  prepareLocalExternalImport,
  prepareNormalizedLocalImport,
} from "../src/index.js";
import type { ExternalFindings } from "../src/external-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { git } from "./git-fixture.js";
import {
  trivyReport,
  trivyRepositoryHeader,
} from "./support/trivy-import-fixtures.js";

const checkoutUrl = "https://github.com/example/project";
const foreignUrl = "https://github.com/example/other";
const enterpriseUrl = "https://git.example.test/Example/Project";
const enterpriseSsh = "git@git.example.test:example/project.git";
const mismatch = "does not match a configured remote";
const ambiguousSsh = /Trivy omitted the SSH user/u;

function repositoryClaims(artifactName: string, repoUrl: string) {
  return { ArtifactName: artifactName, Metadata: { RepoURL: repoUrl } };
}

async function trivyCheckout(remote?: string, githubSource?: string) {
  const fixture = await localFindingsFixture({ remote });
  const options = {
    provider: "trivy" as const,
    repository: fixture.repository,
    sourceKey: "example/project/main",
  };
  const deps = {
    environment: fixture.environment,
    sourceRepositories: githubSource
      ? [{ url: githubSource, platform: "github" as const }]
      : [],
  };
  const file = join(fixture.root, "trivy.json");
  const prepare = (input: ExternalFindings, repository = fixture.repository) =>
    prepareNormalizedLocalImport(input, { ...options, repository }, deps);
  return {
    [Symbol.asyncDispose]: fixture.dispose,
    repository: fixture.repository,
    prepare,
    async fromFile(report: unknown, trivyScanRoot?: string) {
      await writeFile(file, JSON.stringify(report));
      return prepareLocalExternalImport(
        file,
        { ...options, trivyScanRoot },
        deps,
      );
    },
    async fromNormalized(report: unknown, scanRoot?: string) {
      return prepare(normalizeTrivyFindings(report, "cloud", scanRoot));
    },
    list: () => listLocalExternalFindings(options, deps),
  };
}

test("normalized Trivy headers reject credentials before local or Cloud preparation", async () => {
  const input = normalizeTrivyFindings(trivyReport(), "cloud", ".");
  input.report = trivyRepositoryHeader(
    "https://scanner:fixture@github.com/example/other",
  );
  const error = "without credentials";
  await using local = await trivyCheckout(checkoutUrl);
  await expect(local.prepare(input)).rejects.toThrow(error);
  await expect(
    prepareNormalizedExternalPublication(
      input,
      {
        provider: "trivy",
        repository: "repo-example",
        sourceKey: "example/project/main",
      },
      {
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
        credentials: async () => {
          throw new Error("Unexpected Cloud authentication");
        },
      },
    ),
  ).rejects.toThrow(error);
});

test.each([
  ["foreign empty report", {}, foreignUrl, mismatch],
  [
    "empty report with a mixed-case Git helper recorded by Git",
    { Metadata: { RepoURL: "HTTPS://github.com/example/project" } },
    "HTTPS://github.com/example/project",
    null,
  ],
  [
    "empty report with only a mixed-case scanner target",
    { Metadata: {}, ArtifactName: "HTTPS://github.com/example/project" },
    "HTTPS://github.com/example/project",
    "mixed-case HTTP target",
  ],
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
    "unverified Enterprise aliases without a checkout remote",
    repositoryClaims(enterpriseUrl.toLowerCase(), enterpriseSsh),
    undefined,
    "identify different repositories",
  ],
  [
    "case-sensitive HTTPS claims without a GitHub source",
    repositoryClaims(enterpriseUrl, enterpriseUrl.toLowerCase()),
    enterpriseUrl,
    "identify different repositories",
  ],
  [
    "case-sensitive HTTP claims without a GitHub source",
    repositoryClaims(
      "http://git.example.test/Example/Project",
      "http://git.example.test/example/project.git",
    ),
    undefined,
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
  [
    "matching artifact URL only",
    { Metadata: {}, ArtifactName: checkoutUrl },
    checkoutUrl,
    null,
  ],
  [
    "filesystem display URL",
    { ArtifactType: "filesystem", Metadata: {}, ArtifactName: foreignUrl },
    checkoutUrl,
    null,
  ],
  [
    "Windows checkout with a drive-relative origin",
    { ArtifactName: "C:\\ci\\checkout", Metadata: { RepoURL: "D:mirror.git" } },
    checkoutUrl,
    null,
  ],
  ["no report remote", { Metadata: {} }, foreignUrl, null],
  ["no comparable checkout remote", {}, "file:///synthetic/mirror", null],
] as const)(
  "Trivy checks report provenance without accepted findings: %s",
  async (_name, overrides, remote, error) => {
    await using checkout = await trivyCheckout(remote);
    const report = { ...trivyReport(), Results: [], ...overrides };
    for (const prepare of [checkout.fromFile, checkout.fromNormalized]) {
      const pending = prepare(report, ".");
      if (error) await expect(pending).rejects.toThrow(error);
      else {
        const { preview } = await pending;
        expect(preview.findings).toEqual([]);
        expect(preview.excluded).toHaveLength(report.Results.length);
      }
    }
  },
);

test.each([
  [
    "http://git.example.test/example/project.git",
    "http://git.example.test/Example/Project",
    true,
  ],
  [
    "https://git.example.test/example/project.git",
    "https://git.example.test/Example/Project",
    true,
  ],
  [
    "ssh://git.example.test/example/project",
    "ssh://git@git.example.test/example/project",
    false,
  ],
  [
    "ssh://git.example.test/example/other",
    "ssh://git@git.example.test/example/other",
    false,
  ],
  [
    "ssh://git.example.test/example/project",
    "ssh://other@git.example.test/example/project",
    false,
  ],
] as const)(
  "a local GitHub source hint corroborates report %s and artifact %s: %j",
  async (remote, artifact, accepts) => {
    const scheme = remote.startsWith("http:") ? "http" : "https";
    const url = `${scheme}://git.example.test/example/project`;
    await using checkout = await trivyCheckout(url, url);
    const report = { ...trivyReport(), ...repositoryClaims(artifact, remote) };
    for (const prepare of [checkout.fromNormalized, checkout.fromFile]) {
      const pending = prepare(report, ".");
      if (accepts) expect((await pending).preview.findings).toHaveLength(1);
      else await expect(pending).rejects.toThrow(ambiguousSsh);
    }
  },
);

test("a GitHub SSH hint cannot bind a Host alias to an HTTPS checkout", async () => {
  const ssh = "git@work:team/project.git";
  const report = { ...trivyReport(), Metadata: { RepoURL: ssh } };
  await using checkout = await trivyCheckout("https://work/team/project", ssh);
  await expect(checkout.fromNormalized(report, ".")).rejects.toThrow(mismatch);
  git(checkout.repository, "remote", "set-url", "origin", ssh);
  expect(
    (await checkout.fromNormalized(report, ".")).preview.findings,
  ).toHaveLength(1);
});

test("a reader's GitHub web hint cannot change the meaning of the raw Trivy transport", async () => {
  const web = "HTTPS://github.com/example/project";
  await using checkout = await trivyCheckout(checkoutUrl, web);
  for (const raw of [checkoutUrl, web]) {
    const { findings, read, excluded } = normalizeTrivyFindings(
      { ...trivyReport(), ArtifactName: ".", Metadata: { RepoURL: raw } },
      "local",
      ".",
    );
    findings[0]!.evidence.details = { kind: "sast", repository: { url: web } };
    const pending = checkout.prepare({ findings, read, excluded });
    if (raw === checkoutUrl)
      expect((await pending).preview.findings).toHaveLength(1);
    else await expect(pending).rejects.toThrow("different repositories");
  }
});

test("a reader-declared Trivy source must agree with the finding even when both are checkout remotes", async () => {
  await using checkout = await trivyCheckout(checkoutUrl, foreignUrl);
  git(checkout.repository, "remote", "add", "upstream", foreignUrl);
  await expect(checkout.fromNormalized(trivyReport(), ".")).rejects.toThrow(
    "different repositories",
  );
});

test("selected and stored Trivy findings retain their artifact-only checkout binding", async () => {
  await using source = await trivyCheckout(checkoutUrl);
  await using other = await trivyCheckout(foreignUrl);
  const artifact = "ssh://git@github.com/example/project.git";
  const report = trivyReport();
  report.Results.push({
    ...report.Results[0]!,
    Target: "nested/package-lock.json",
  });
  const input = normalizeTrivyFindings(
    { ...report, ArtifactName: artifact, Metadata: {} },
    "local",
    ".",
  );
  const prepared = await source.prepare(input);
  const reloaded = JSON.parse(JSON.stringify(prepared.preview));
  await prepared.import();
  const stored = await source.list();
  expect(stored).toHaveLength(2);
  const record = stored[0]!;
  expect(record.evidence.source_data).toMatchObject({
    report: { ArtifactName: artifact },
  });
  const storedFinding = {
    source_finding_id: record.sourceFindingId,
    evidence: record.evidence,
  };
  for (const selected of [
    reloaded,
    { read: 1, findings: [input.findings[0]!], excluded: [] },
    { read: 1, findings: [storedFinding], excluded: [] },
  ])
    await expect(source.prepare(selected, other.repository)).rejects.toThrow(
      mismatch,
    );
});

test("Trivy import preserves the occurrence across revisions without assessing it", async () => {
  await using checkout = await trivyCheckout(
    "git@github.com:example/project.git",
  );
  const report = trivyReport();
  const prepare = () => checkout.fromFile(report, ".");
  const preview = await prepare();
  expect(preview.preview.excluded).toEqual([]);
  expect(await checkout.list()).toEqual([]);
  expect((await preview.import()).counts.created).toBe(1);
  expect((await (await prepare()).import()).counts.unchanged).toBe(1);

  const updatedCommit = "b".repeat(40);
  report.Metadata.Commit = updatedCommit;
  expect((await (await prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  const stored = await checkout.list();
  expect(stored).toHaveLength(1);
  expect(stored[0]).toMatchObject({
    provider: "trivy",
    sourceFindingId: preview.preview.findings[0]!.source_finding_id,
    version: 2,
    evidence: {
      code_revision: null,
      source_data: { report: { Metadata: { Commit: updatedCommit } } },
    },
    assessment: { state: "not_assessed" },
  });
});

test("local Trivy paths use the checkout root even without a report remote", async () => {
  await using checkout = await trivyCheckout();
  const nested = join(checkout.repository, "apps", "web");
  await mkdir(nested, { recursive: true });
  const findings = normalizeTrivyFindings(
    { ...trivyReport(), Metadata: {} },
    "local",
    "apps/web",
  );
  await expect(checkout.prepare(findings, nested)).rejects.toThrow(
    `Git found the checkout at ${JSON.stringify(checkout.repository)}.`,
  );
  await expect(
    checkout.prepare(findings, join(checkout.repository, ".git", "objects")),
  ).rejects.toThrow("must be run in a work tree");
  const { preview } = await checkout.prepare(findings);
  expect(
    join(preview.repository, preview.findings[0]!.evidence.locations![0]!.path),
  ).toBe(join(nested, "package-lock.json"));
});

test("Trivy distinguishes a differently cased checkout alias from a separate directory", async () => {
  await using checkout = await trivyCheckout();
  const alternate = join(dirname(checkout.repository), "REPOSITORY");
  const created = await mkdir(alternate, { recursive: true });
  git(checkout.repository, "config", "core.worktree", alternate);
  const prepared = checkout.fromNormalized(trivyReport(), ".");
  if (created)
    await expect(prepared).rejects.toThrow(
      "Trivy finding paths are checkout-relative",
    );
  else expect((await prepared).preview.findings).toHaveLength(1);
});

test.each([
  [foreignUrl, checkoutUrl, undefined, false],
  [enterpriseUrl, enterpriseSsh, enterpriseUrl, true],
] as const)(
  "normalized Trivy report %s and finding %s must agree without a checkout remote",
  async (reportUrl, findingUrl, githubSource, matches) => {
    await using checkout = await trivyCheckout(undefined, githubSource);
    const plainDirectory = join(dirname(checkout.repository), "unpacked");
    await mkdir(plainDirectory);
    const input = normalizeTrivyFindings(
      { ...trivyReport(), Metadata: { RepoURL: findingUrl } },
      "local",
      ".",
    );
    input.report = trivyRepositoryHeader(reportUrl);
    for (const repository of [checkout.repository, plainDirectory]) {
      const prepared = checkout.prepare(input, repository);
      if (matches) expect((await prepared).preview.findings).toHaveLength(1);
      else await expect(prepared).rejects.toThrow("different repositories");
    }
  },
);

test.each([
  [checkoutUrl, foreignUrl, true, false],
  [
    "git@git.example.test:/example/project",
    "git@git.example.test:example/project",
    false,
    false,
  ],
  [
    "tenant-a@git.example.test:project",
    "tenant-b@git.example.test:project",
    true,
    false,
  ],
  [
    "alice@git.example.test:project.git",
    "alice@git.example.test:project",
    true,
    false,
  ],
  [
    "git@github.com:example/project.git",
    "ssh://git@github.com/example/project?",
    true,
    false,
  ],
  [checkoutUrl, "g:team/two", false, process.platform === "win32"],
  ["user@g:team/one", "user@g:team/two", false, false],
  [
    "ssh://github.com/example/project",
    "git@github.com:example/project.git",
    false,
    ambiguousSsh,
  ],
  [
    checkoutUrl,
    "https://checkout-user@github.com/example/project.git",
    false,
    true,
  ],
  [
    checkoutUrl,
    "https://checkout-user@github.com/example/other.git",
    false,
    false,
  ],
  [
    "ssh://tenant.ghe.com/team/project",
    "ssh://tenant@tenant.ghe.com/team/project",
    false,
    ambiguousSsh,
  ],
  [
    "ssh://tenant.ghe.com/team/project",
    "ssh://other@tenant.ghe.com/team/project",
    false,
    ambiguousSsh,
  ],
  [checkoutUrl, "ssh://github.com/example/project", false, false],
  [checkoutUrl, "ssh://git@github.com/example/project", false, true],
  [checkoutUrl, "SSH://github.com/example/project", false, false],
  [checkoutUrl, "HTTPS://github.com/example/project", false, false],
  [checkoutUrl, "git+ssh://git@github.com/example/project.git", false, true],
  [checkoutUrl, "ssh+git://git@github.com/example/project.git", false, true],
  [
    enterpriseUrl,
    "https://checkout-user@git.example.test/Example/Project",
    false,
    false,
  ],
  [
    enterpriseUrl,
    "https://checkout-user@git.example.test/Example/Project",
    true,
    true,
  ],
  [enterpriseUrl, enterpriseUrl.toLowerCase(), true, true],
  [enterpriseUrl, enterpriseUrl.toLowerCase(), false, false],
] as const)(
  "Trivy checks source %s against checkout %s (GitHub hint %j, match %j)",
  async (source, checkout, githubHint, matches) => {
    await using local = await trivyCheckout(
      checkout,
      githubHint ? source : undefined,
    );
    const report = trivyReport();
    report.Metadata.RepoURL = source;
    const pending = local.fromFile(report, ".");
    if (matches === true)
      expect((await pending).preview.findings).toHaveLength(1);
    else await expect(pending).rejects.toThrow(matches || mismatch);
  },
);

test.each([
  { ArtifactName: checkoutUrl.replace("https:", "HTTPS:"), Metadata: {} },
  {
    ArtifactName: ".",
    Metadata: { RepoURL: "ssh://github.com/example/project" },
  },
  repositoryClaims(
    "ssh://alice@source.example/team/project",
    "ssh://source.example/team/project",
  ),
])(
  "unresolved Git transport can be retained in an unverified local import",
  async (source) => {
    await using checkout = await trivyCheckout("file:///local/fixture.git");
    const unpacked = join(dirname(checkout.repository), "unpacked");
    await mkdir(unpacked);
    const report = { ...trivyReport(), ...source };
    const { findings, read, excluded } = normalizeTrivyFindings(
      report,
      "local",
      ".",
    );
    const stored = await checkout.prepare(
      { findings, read, excluded },
      unpacked,
    );
    expect(stored.preview.findings).toEqual(findings);
    expect((await checkout.fromFile(report, ".")).preview.findings).toEqual(
      findings,
    );
  },
);

test.each([
  "ssh://alice@elsewhere.example/team/unrelated",
  "ssh://alice@source.example/team/unrelated",
])(
  "an omitted SSH user cannot explain the conflicting Trivy target %s",
  async (artifact) => {
    await using checkout = await trivyCheckout();
    const report = {
      ...trivyReport(),
      ...repositoryClaims(artifact, "ssh://source.example/team/project"),
    };
    expect(() => normalizeTrivyFindings(report)).toThrow("--trivy-scan-root");
    const { read, excluded, findings } = normalizeTrivyFindings(
      report,
      "local",
      ".",
    );
    for (const prepare of [
      () => checkout.fromFile(report, "."),
      () => checkout.prepare({ read, excluded, findings }),
    ])
      await expect(prepare()).rejects.toThrow("different repositories");
  },
);
