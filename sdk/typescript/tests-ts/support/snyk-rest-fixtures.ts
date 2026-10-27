import type {
  SnykIssuesExport,
  SnykIssuesProduct,
} from "../../src/snyk-rest-findings.js";

export const organizationId = "11111111-1111-4111-8111-111111111111";
export const projectId = "22222222-2222-4222-8222-222222222222";
export const targetId = "33333333-3333-4333-8333-333333333333";
export const issueId = "44444444-4444-4444-8444-444444444444";
export const apiOrigin = "https://api.eu.snyk.io";
export const sourceRepositoryUrl = "https://github.com/example/repository";

export function snykRestProject({
  manager = "npm",
  origin = "github",
  remote = sourceRepositoryUrl + ".git",
  expanded = true,
  id = projectId,
  org = organizationId,
}: {
  manager?: string;
  origin?: string;
  remote?: string | null;
  expanded?: boolean;
  id?: string;
  org?: string;
} = {}) {
  return {
    id,
    type: "project",
    attributes: {
      type: manager,
      name: "example/project:manifest",
      origin,
      target_reference: "release",
      target_file: manager === "sast" ? "" : "app/package.json",
    },
    relationships: {
      organization: { data: { type: "org", id: org } },
      target: {
        data: {
          type: "target",
          id: targetId,
          ...(expanded && {
            attributes: {
              display_name: "https://example.invalid/not-a-repository-claim",
              url: remote,
            },
          }),
        },
        links: { related: { href: "https://unrelated.invalid/targets" } },
      },
    },
  };
}

export function snykRestIssue(
  attributes: Record<string, unknown> = {},
  {
    id = issueId,
    org = organizationId,
    project = projectId,
    itemType = "project",
  } = {},
) {
  return {
    id,
    type: "issue",
    attributes: {
      type: "package_vulnerability",
      key: "opaque-key",
      title: "Synthetic issue",
      effective_severity_level: "high",
      status: "resolved",
      ignored: false,
      created_at: "2025-01-01T00:00:00Z",
      updated_at: "2025-02-03T04:05:06.123Z",
      ...attributes,
    },
    relationships: {
      organization: { data: { type: "organization", id: org } },
      scan_item: { data: { type: itemType, id: project } },
    },
  };
}

export function snykRestDocument(data: unknown, next?: unknown) {
  return {
    jsonapi: { version: "1.0" },
    data,
    ...(next !== undefined && { links: { next } }),
  };
}

export function snykRestFixture(
  product: SnykIssuesProduct,
  {
    sourceRepositoryUrl: repository = sourceRepositoryUrl,
    title = "Synthetic issue",
    updatedAt = "2025-02-03T04:05:06.123Z",
    empty = false,
  }: {
    sourceRepositoryUrl?: string;
    title?: string;
    updatedAt?: string;
    empty?: boolean;
  } = {},
) {
  const code = product === "code";
  const selectedId = code ? "66666666-6666-4666-8666-666666666666" : projectId;
  const representation = code
    ? {
        sourceLocation: {
          file: "src/example.ts",
          commit_id: "synthetic-commit",
        },
      }
    : {
        dependency: { package_name: "@example/pkg", package_version: "1.0.0" },
      };
  const finding = snykRestIssue(
    {
      type: code ? "code" : "package_vulnerability",
      key: "opaque-key",
      title,
      ignored: true,
      updated_at: updatedAt,
      problems: [
        {
          source: "Snyk",
          type: "rule",
          id: code ? "example-rule" : "SNYK-EXAMPLE-1",
        },
      ],
      coordinates: [{ representations: [representation] }],
    },
    { project: selectedId },
  );
  return {
    format: "snyk-rest-issues/v1",
    apiVersion: "2026-03-25",
    apiOrigin,
    product,
    organizationId,
    projectId: selectedId,
    sourceRepositoryUrl: repository,
    complete: true,
    project: snykRestProject({
      manager: code ? "sast" : "npm",
      id: selectedId,
      remote: repository,
    }),
    target: null,
    pages: [
      {
        startingAfter: null,
        response: snykRestDocument(empty ? [] : [finding]),
      },
    ],
  } satisfies SnykIssuesExport;
}
