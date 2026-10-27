---
name: resolve-dependency-alert
description: Investigate vulnerable packages from scanner reports, advisories or SBOM matches. Trace affected versions and prepare an upgrade or a dismissal for human review.
---

# Resolve a dependency alert

## Get the alert

For an import, start with [$publish-findings](../publish-findings/SKILL.md) before fetching. It checks opt-in and previews supported formats for approval. Read existing local imports with `codex-security findings imported <repo> --format json`.

For assessment, read the supplied report even if its format has no importer. Route reported malware to incident response. To discover alerts, query the named scanner for the selected repository or image, follow pagination and report incomplete reads. Keep each scanner's alert ID or the export digest and record position. For Dependabot, use the [vulnerability alerts endpoint](../triage-finding/references/github-rest-intake.md#dependabot-vulnerabilities).

## Trace and fix

1. Find each copy, its origin (registry, local path or fork) and its parent path. Record the checkout revision and any lockfile digests, or the image digest. Check where the vulnerable behavior runs, including build and CI jobs.
2. Read the lockfile directly in static mode. Otherwise use the project's pinned resolver in isolation and check the lockfile for omitted scopes or platforms. For npm use `npm ls --package-lock-only --all --include=dev --include=optional --include=peer --json`. For pnpm use `pnpm list --recursive --include-workspace-root --depth Infinity --lockfile-only --json`.
3. Match the package origin and any backport to the advisory. Check the installed version and each candidate against every affected range. Look for an existing fix PR. If the user asks whether an upgrade is possible, explain whether it takes a lockfile refresh, a direct or parent bump, or a migration. Name any blocker.
4. Match cooldowns and exclusions to the package, directory and update type for every covered release, including transitive dependencies. Dependabot's cooldown governs version updates. Repository instructions, package-manager settings or CI may also gate security or manual merges. Give the earliest eligible merge time in UTC using registry publication dates or CI. Missing required dates hold the merge. Testing can proceed.
5. Edit dependencies only when the user requests an upgrade. Give [$fix-finding](../fix-finding/SKILL.md) the affected version, advisory revision and planned change. State any uncertainty about application reachability. Compare the graph before and after. In standard mode verify a clean install, the affected behavior and a legitimate caller.

## Report the outcome

Group alerts that share a fix and keep their IDs. State the outcome for the checkout, build or deployment examined.

- **Fixed.** Verify replacement or removal. For a deployment, confirm the replacement actually rolled out.
- **Not affected.** Cite proof, such as a backport in the scanned package. A missing call site or passing tests alone leave the alert open.
- **Mitigated.** Identify the deployed control, remaining exposure, owner and review date.
- **Risk accepted.** Cite the authorized human decision, scope, owner and expiry.
- **Unresolved.** Name the affected copy or missing evidence and who can act on it.

For a proposed dismissal, give the reviewer the alert, provider reason, evidence and when to recheck it. Only an authorized human approves and executes the dismissal in the scanner.
