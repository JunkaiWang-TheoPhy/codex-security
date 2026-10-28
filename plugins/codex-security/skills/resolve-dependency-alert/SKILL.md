---
name: resolve-dependency-alert
description: Investigate a vulnerable dependency from a scanner alert, advisory, or SBOM match. Trace what pulls it in and determine whether it can be upgraded.
---

# Resolve a dependency alert

Start with the supplied report and the checkout or image the user wants assessed. Read the report as evidence even if there is no importer.

For an explicit import request, use [$publish-findings](../publish-findings/SKILL.md). If the user asks to discover alerts, query only the selected scanner and target, follow pagination, and report incomplete reads. For Dependabot, follow the [GitHub intake workflow](../triage-finding/references/github-rest-intake.md#dependabot-vulnerabilities). Refer reported malware to incident response.

1. Trace each affected copy to its manifest and parent dependency. Use the lockfile, image inventory, or project's package manager to establish its origin, resolved version, and where it runs, including build, optional, and platform-specific dependencies. In static mode, inspect existing evidence without executing project tooling.
2. Check the advisory's affected ranges and any distribution backport against each copy and proposed replacement. Look for an existing fix. Explain whether a lockfile refresh, direct upgrade, or parent upgrade suffices, and flag any compatibility blocker. Apply the repository's cooldowns and exclusions where they govern that update. If release age blocks a merge, give the eligible date or identify the missing publication date.
3. Edit only when the user requests an upgrade. Hand the evidence and proposed change to [$fix-finding](../fix-finding/SKILL.md) in the selected verification mode. Compare the resolved copies before and after.

Report the alert IDs or source records, the checkout revision or image digest, and the evidence for each outcome. Distinguish a verified fix in the checkout from a deployed fix. A verified backport can establish that a package is unaffected. A mitigation leaves residual exposure, and risk acceptance requires a recorded human decision.

When evidence is missing, leave the alert open and say what would resolve it. For a proposed dismissal, give the provider reason, evidence, and when to recheck. Only an authorized human approves and executes the dismissal.
