import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import schema from "../../../plugins/codex-security/schemas/dependency-resolution.schema.json";

const validate = new Ajv2020({ strict: false }).compile(schema);
const result = {
  sourceId: "grype/sample-image/match-1",
  sourceVersion: "snapshot-1",
  scope: "deployment",
  subjectVersion: null,
  package: "pkg:pypi/example-parser@1.0.0",
  dependencyPaths: [],
  applicability: "unknown",
  disposition: "unresolved",
  evidence: ["The scanner matched the image. Its rollout is unknown."],
  gaps: ["Which workload runs this image?"],
  checks: [],
  nextAction: "Verify the deployed digest.",
};

test("a scanner occurrence can stay unresolved while a patched release waits for the repository cooldown", () => {
  const upgrade = {
    candidate: "example-parser@1.0.1",
    cooldown: "waiting",
    policyEvidence: "Seven days from publication at 2026-10-25T12:00:00Z.",
  };
  const report = (candidate: typeof upgrade & { eligibleAt?: string }) => ({
    schemaVersion: "dependency-resolution/v0",
    results: [{ ...result, upgrade: candidate }],
  });
  expect(
    validate(report({ ...upgrade, eligibleAt: "2026-11-01T12:00:00Z" })),
  ).toBe(true);
  expect(validate(report(upgrade))).toBe(false);
});

test("a fixed checkout and an unverified deployment retain separate outcomes, and risk acceptance needs a human decision", () => {
  const checkout = {
    ...result,
    scope: "checkout",
    subjectVersion: "fixture-after-upgrade",
    applicability: "not_affected",
    disposition: "fixed",
    evidence: ["The verified candidate removed the affected copy."],
  };
  const report = (deployment: object) => ({
    schemaVersion: "dependency-resolution/v0",
    results: [checkout, deployment],
  });
  expect(validate(report(result))).toBe(true);
  expect(
    validate(
      report({
        ...result,
        disposition: "fixed",
        applicability: "not_affected",
      }),
    ),
  ).toBe(false);
  const accepted = {
    ...result,
    subjectVersion: "image-digest-1",
    disposition: "risk_accepted",
    owner: "service owner",
    reviewBy: "2026-11-01",
  };
  expect(validate(report(accepted))).toBe(false);
  expect(
    validate(report({ ...accepted, approvalRef: "synthetic-decision-1" })),
  ).toBe(true);
});
