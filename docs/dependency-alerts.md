# Assess dependency alerts

Use `$resolve-dependency-alert` in a Codex Security plugin session to trace a
reported vulnerable package and evaluate an upgrade. Supply the scanner report
and the checkout or image you want assessed. The skill reads formats without an
importer directly; assessment does not require a Cloud connection or import.

Assessment leaves the target unchanged and uses existing lockfiles, manifests,
or image inventories. If those files cannot establish the resolved dependencies,
the result identifies the missing evidence. Request an upgrade explicitly when
you want the skill to hand the change to `$fix-finding`.

## Container images

Provide the exported report, the selected image's repository digest and
platform, and its package inventory or SBOM when available. An inventory from a
different image cannot establish the selected image's installed packages.

For example, with those files available in the session:

> Use $resolve-dependency-alert on trivy.json and inventory.json for the
> linux/amd64 image identified in the inventory. Explain what introduces each
> affected package and which upgrades would fix it. Assess only; do not edit
> files, rebuild the image, or contact the registry.

Review each package occurrence, including copies in application dependencies,
bundled tools, and the base image. Two copies with the same advisory may need
different changes. Distribution packages can include backported fixes, so use
the matching distribution advisory rather than comparing only upstream
versions. A scanner's `fixed` status can mean that a fixed version is available;
compare that version with the installed version before concluding remediation.

The assessment should identify the report records, exact image digest, and the
path and content digest of each inventory used. Keep a proposed package change,
a rebuilt image, and a verified deployment separate. Testing or editing a
checkout alone does not establish that a deployed image is fixed.

## Existing Trivy Operator reports

For an offline assessment after a rollout, supply the exported
`VulnerabilityReport` and the selected pod's export, including container image
IDs. Include an inventory or report for the currently running image if you have
one.

> Use $resolve-dependency-alert to assess operator-report.json against pod.json.
> Does this evidence justify closing the alert for the selected app container
> after the rollout? Explain any missing evidence. Do not contact the cluster,
> change the workload, or dismiss the alert.

Compare the report's artifact digest with the current container's resolved image
identity. The same mutable tag does not establish that they are the same image.
A recently updated report can still concern an older image or ReplicaSet, and
its update time does not establish vulnerability database freshness. An image
configuration ID and a repository manifest digest are different identifiers;
do not treat their differing values as proof of a different image.

If the report concerns the previous image, keep its findings scoped to that
image and identify the evidence needed for the current one. A rollout by itself
does not establish that the replacement contains the fixed package. Only an
authorized human approves and executes a dismissal in the scanner.

## Import and remediation are separate requests

For a supported report that you explicitly want to persist, use
[`$publish-findings`](../plugins/codex-security/skills/publish-findings/SKILL.md)
and its existing opt-in and preview flow. The direct assessment examples above
do not imply a native Trivy or Trivy Operator importer.

For an upgrade, provide the proposed change, original finding, and target to
[`$fix-finding`](../plugins/codex-security/skills/fix-finding/SKILL.md). Repository
release-age policies still apply. Missing publication dates leave a
cooldown-gated merge blocked, even when a compatible fixed version exists.
