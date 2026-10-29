import { hostedRepositoryUrlKey } from "../src/external-import-contract.js";
import { expect, test } from "bun:test";
import {
  isGitHubCloudHost,
  normalizeHostedGitRepositoryUrl,
  parseGitRemote,
} from "../src/git-remote.js";

test.each([
  [
    "https://example.test/team/project.git",
    false,
    "https:",
    "",
    "",
    "team/project.git",
  ],
  [
    "ssh://git@example.test:2222/team/project.git",
    false,
    "ssh:",
    "git",
    "2222",
    "team/project.git",
  ],
  [
    "git@example.test:team/project.git",
    true,
    "ssh:",
    "git",
    "",
    "team/project.git",
  ],
  ["example.test:team/project.git", true, "ssh:", "", "", "team/project.git"],
] as const)(
  "parses the transport of %s",
  (input, scpStyle, protocol, username, port, path) => {
    const remote = parseGitRemote(input)!;
    expect(remote).toMatchObject({ scpStyle, path });
    expect(remote.url.hostname).toBe("example.test");
    expect(remote.url.protocol).toBe(protocol);
    expect(remote.url.username).toBe(username);
    expect(remote.url.port).toBe(port);
  },
);

test("keeps literal SCP paths separate from URL queries and fragments", () => {
  const remote = parseGitRemote(
    "git@example.test:team/../project.git?ref#part",
  )!;
  expect(remote.path).toBe("team/../project.git?ref#part");
  expect(remote.url.search).toBe("");
  expect(remote.url.hash).toBe("");
});

test("uses URL path semantics while preserving repository casing", () => {
  const remote = parseGitRemote("https://example.test/Team/../Project.git/")!;
  expect(remote.path).toBe("Project.git/");
  expect(remote.url.pathname).toBe("/Project.git/");
});

test("leaves transport and credential eligibility to callers", () => {
  const remote = parseGitRemote(
    "http://synthetic:password@example.test/team/project?ref#part",
  )!;
  expect(remote.url.protocol).toBe("http:");
  expect(remote.url.username).toBe("synthetic");
  expect(remote.url.password).toBe("password");
  expect(remote.url.search).toBe("?ref");
  expect(remote.url.hash).toBe("#part");
});

test("preserves IPv6 hosts and explicit SSH ports", () => {
  const remote = parseGitRemote(
    "ssh://git@[2001:db8::1]:2222/team/project.git",
  )!;
  expect(remote.url.hostname).toBe("[2001:db8::1]");
  expect(remote.url.port).toBe("2222");
  expect(remote.path).toBe("team/project.git");
});

test("distinguishes plain paths and malformed URLs", () => {
  expect(parseGitRemote("./team/project")).toBeUndefined();
  expect(() => parseGitRemote("https://[invalid/team/project")).toThrow();
});

test.each([
  ["github.com", true],
  ["example-enterprise.ghe.com", true],
  ["ghe.com", false],
  ["github.example.test", false],
  ["github.com.example.test", false],
  ["example-enterprise.ghe.com.example.test", false],
] as const)("recognizes GitHub Cloud host %s", (host, expected) => {
  expect(isGitHubCloudHost(host)).toBe(expected);
});

test.each([
  ["ssh", "github.com", "My%2DRepo", "my%2Drepo", true],
  ["ssh", "github.com", "my-repo", "my%2Drepo", true],
  ["ssh", "github.com", "my%2Drepo", "my-repo", true],
  ["scp", "github.com", "my%2Drepo", "my%2Drepo", false],
  ["scp", "gitlab.com", "my%2frepo", "my%252Frepo", false],
  ["scp", "gitlab.com", "my%2Frepo", "my%252Frepo", true],
  ["ssh", "github.com", "my%252Drepo", "my%2Drepo", false],
  ["ssh", "github.com", "my%2Frepo", "my%2Frepo", false],
  ["ssh", "gitlab.com", "My-repo", "my%2Drepo", false],
] as const)(
  "compares %s bytes on %s (%s, %s)",
  (scheme, host, path, expected, matches) => {
    const source = `https://${host}/org/${expected}`;
    const remote =
      scheme === "scp"
        ? `git@${host}:org/${path}.git`
        : `ssh://git@${host}/org/${path}.git`;
    const alias = normalizeHostedGitRepositoryUrl(remote, source, false);
    expect(
      hostedRepositoryUrlKey(alias) === hostedRepositoryUrlKey(source),
    ).toBe(matches);
  },
);

test.each([
  ["ssh://g%69t@%67ithub.com", true],
  ["ssh://git@github%2Ecom:2%32", true],
  ["ssh://%67it@ssh.github.com:443", true],
  ["ssh://git@github.com%3A22", true],
  ["ssh://git@ssh.github.com%3a443", true],
  ["ssh://git@github.com%3A2222", false],
  ["ssh://git@github.com%253A22", false],
  ["ssh://git@github.com%40other", false],
  ["ssh://git@github.com%2Fother", false],
  ["ssh://git@github.com%23suffix", false],
  ["ssh://g%00it@github.com", false],
  ["ssh://git@github.com ", false],
  ["ssh://git@%2567ithub.com", false],
] as const)("compares Git SSH authority %j", (authority, matches) => {
  const source = "https://github.com/org/repo";
  const remote = authority + "/org/repo";
  expect(normalizeHostedGitRepositoryUrl(remote, source, false)).toBe(
    matches ? source : remote,
  );
});

test.each([
  ["/org/my%2Drepo", "/org/my-repo", true],
  ["/org/%252Drepo", "/org/%2Drepo", false],
  ["/org/my%2Frepo", "/org/my/repo", false],
  ["/org/my%2frepo", "/org/my%2Frepo", true],
  ["/org/%2e%2E/repo", "/org/%2E%2e/repo", true],
  ["/org/my%252frepo", "/org/my%252Frepo", false],
  ["/org/%2e%2e/repo", "/org/../repo", false],
  ["/org/my%2Drepo?x=%2D#%41", "/org/my-repo?x=-#A", false],
  ["/Org/my%2Drepo", "/org/my-repo", false],
] as const)("compares hosted paths %j and %j", (first, second, matches) => {
  const host = "https://scm.example.test";
  expect(
    hostedRepositoryUrlKey(host + first) ===
      hostedRepositoryUrlKey(host + second),
  ).toBe(matches);
});

test("recognizes bracketed IPv6 SCP authorities on a verified Enterprise host", () => {
  const source = "https://[2001:db8::1]/org/repo";
  const remote = "git@[2001:db8::1]:org/repo";
  expect(normalizeHostedGitRepositoryUrl(remote, source, true)).toBe(source);
  expect(normalizeHostedGitRepositoryUrl(remote, source, false)).toBe(remote);
  for (const other of [
    "other@[2001:db8::1]:org/repo",
    "git@[2001:db8::2]:org/repo",
  ])
    expect(normalizeHostedGitRepositoryUrl(other, source, true)).toBe(other);
});
