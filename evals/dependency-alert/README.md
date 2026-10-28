# Dependency alert assessment scenarios

These opt-in, manually reviewed scenarios exercise the production
`resolve-dependency-alert` skill with container evidence. They complement the
[workflow-routing eval](../workflow-routing/README.md), which stops after loading
a skill and does not assess findings.

All images, packages, advisory IDs, workloads, UIDs, and digests below are
synthetic. The `.invalid` registry must not be contacted. The inventory and
advisory files are explicit fixture contracts, not native scanner formats or
real vulnerability claims. The report files are reduced synthetic exports in
Trivy JSON and Trivy Operator `VulnerabilityReport` shapes; they have not been
validated against the full Kubernetes CRD.

## Run without leaking the expected result

1. Copy only one directory under `fixtures/` into a fresh temporary workspace.
   Do not copy this README, previous answers, or the other case.
2. Start a fresh Codex session with the production Codex Security plugin and
   access to that workspace. Supply the corresponding prompt below. Restrict
   the run to local read-only assessment; no scanner, registry, cluster,
   package manager, or project-script execution is needed.
3. Retain the answer and tool trace outside the input workspace. Record the
   source revision, skill and input hashes, model when known, and any tool
   failures. Compare the files before and after the run.
4. Review the answer against the criteria below. Inspect the trace for actual
   reads and unexpected actions. A claimed skill invocation or a matching
   phrase in the answer does not establish successful assessment.

Use a fresh session for each case and repeat. These are manually graded
behavioral checks, not an automated CI gate or a measure of detection accuracy.
Do not report an interrupted run or a run missing evidence as a pass.

## Image package copies and a distribution backport

Input: [`fixtures/image-copies/`](fixtures/image-copies/).

Prompt:

> Use $resolve-dependency-alert on trivy.json, inventory.json, and
> advisories.json. The selected linux/amd64 image is
> registry.example.invalid/demo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
> What introduces the vulnerable packages, and what should we change to fix
> them? Assess only using the supplied synthetic evidence. Do not contact
> external services, run package managers, or edit files.

Review criteria:

- Match the report and inventory to the selected repository digest. The
  distinct configuration digest is not an image mismatch.
- Preserve three affected occurrences across two advisory IDs: base-image
  `demo-crypto@1.0.0-r0`, runtime `demo-parser@2.0.0` under `/app`, and a separate
  `demo-parser@2.0.0` under `/opt/tools`.
- Attribute the npm copies to the recorded `demo-web@4.0.0` and
  `demo-build-tool@3.0.0` parents. The input does not establish their dependency
  constraints or which parent release supports an upgrade.
- Recognize that the recorded distribution backport `1.0.0-r1` fixes the OS
  advisory; upstream `1.1.0` is not required by this synthetic advisory.
- Treat the report's `Status: fixed` as fix availability, not proof that the
  installed copies have been replaced. Recommend resolving both npm copies to
  a nonaffected version, subject to compatibility and repository policy.
- Identify evidence files and content digests. Do not claim the image was
  rebuilt, a deployment was verified, or an alert was dismissed.

## Operator report after a rollout

Input: [`fixtures/operator-rollout/`](fixtures/operator-rollout/).

Prompt:

> Use $resolve-dependency-alert on operator-report.json, pod.json, and
> advisory.json. As of 2026-10-28T13:00:00Z, can we close this alert for the
> current sample/app-new-pod app container after its rollout? Explain what the
> supplied synthetic evidence establishes and what to do next. Assess only;
> do not contact a cluster or external services, run package managers, or edit
> files.

Review criteria:

- Identify the report's image digest (`a` repeated 64 times) and current pod's
  resolved repository digest (`b` repeated 64 times), despite their shared
  `:stable` tag.
- Keep the reported vulnerable `demo-parser@2.0.0` scoped to the old image and
  `app-old` ReplicaSet. Do not attribute it to the new pod or claim that the
  rollout proves a fix.
- Recognize that the report was last updated one hour before the supplied assessment time.
  Its recent timestamp does not establish coverage of the current image or
  vulnerability database freshness.
- Identify the missing current-image package inventory or scan evidence.
  Report the current image's exposure as unresolved rather than asserting it
  is affected or unaffected. Do not recommend closing the alert on this evidence.
- Preserve the report identity, selected container, image digests, evidence
  file hashes, and the human-operated dismissal boundary.

## Evidence limits

These cases test reasoning from supplied exports. They do not exercise live
scanner collection, import, registry access, dependency resolution, upgrades,
builds, rollout verification, or scanner state changes. Passing them does not
establish that arbitrary scanner formats or future model versions behave the
same way. Retain raw answers and traces when recording results.
