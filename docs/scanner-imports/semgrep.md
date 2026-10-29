# Import Semgrep findings

Vendor finding import and readback require `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`.
See the [opt-in instructions](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
and [how saved scanner reports map to imported evidence](schema-guide.md).

## Existing Platform findings

Set `SEMGREP_APP_TOKEN` to a Web API token for `https://semgrep.dev`. If
`SEMGREP_URL` or its fallback `SEMGREP_APP_URL` is set, it must identify that
origin. Select the deployment slug, exact project name and ref. Use `sast` for
Code (the default), `sca` for Supply Chain or `ai_sast` for AI-powered detections.

```sh
codex-security import semgrep example/project --semgrep-deployment example \
  --semgrep-ref refs/heads/main --format json > platform.json &&
codex-security publish findings platform.json --to local --provider semgrep \
  --repository ./project --source-key example/project/main/platform-sast --dry-run
```

The collector resolves the SCM URL and reads all pages for the selected
project ID, ref and product. For collections spanning multiple pages, it checks
for overlapping finding IDs and rereads the first page. Retry if either check
detects a change. The API does not provide an atomic snapshot, so concurrent
changes confined to later pages can still cause findings to be skipped.
If the project has no SCM URL or supplies an SSH clone URL, provide
its HTTP(S) URL with `--source-repository-url`. The report keeps the native URL
and mapping. Both SSH clones and case-only path differences on custom hosts
require a verified GitHub binding at import. The project ID scopes collection.
A URL-less row may carry an independently configured repository name, so the
collector records those additional names for replay. Rows may omit the repository
or ref. Imports use the selected scope for omitted fields and check supplied
values against it.
This endpoint excludes removed findings and Secrets. [Project API](https://docs.semgrep.dev/api-reference/v1/projectsservice/get-project-details)
and [Findings API](https://docs.semgrep.dev/api-reference/v1/findingsservice/list-code-supply-chain-or-ai-powered-detection-findings).

The SDK exposes `collectSemgrepPlatformFindings` and
`normalizeSemgrepPlatformFindings`. Finding IDs retain their exact integer
value, scoped to deployment, project ID, ref and product. Reimport with the
same source key to refresh imported triage, locations or dependency evidence.
Keep a separate key for CLI scans. Individual API pages and Guardian/MCP
summaries are unsupported.

## CLI and CI scans

Prefer native **Semgrep Code/SAST CLI or CI JSON** for a new scan. It preserves
the scanner's original severity and source evidence. Self-contained SARIF 2.1.0
is a compatibility path. Both formats may be plain or gzip-compressed.

Run the following from the source repository root with your selected SAST rules.

```sh
semgrep scan --config /path/to/sast-rules.yaml --json-output semgrep.json .
codex-security publish findings semgrep.json --to local \
  --provider semgrep --source-key ORGANIZATION/PROJECT/BRANCH \
  --source-repository-url https://github.com/example/project \
  --repository . --dry-run --format json
```

Existing CI jobs can add `--json-output semgrep.json` to their SAST scan and pass
that artifact to the publisher. With authenticated `semgrep ci`, select `--code`;
its output follows the job's policy and PR/baseline scope and may contain only new
blocking findings. It is not a complete inventory of Platform findings.
[CLI output and scope reference](https://docs.semgrep.dev/cli-reference).

Review the findings, source repository and exclusions, then repeat the command
without `--dry-run` and confirm the import, or add `--yes` after review. Local
imports require no Cloud login and store unassessed evidence in the workbench
SQLite database. Read it with `codex-security findings imported . --format json`.
Repeated imports with the same source identity update the same records; omitted
records remain stored. See the movement behavior under Evidence and identity.
They do not create a completed scan or automatically assess or patch findings.

For Cloud, use the same report and source selection with a Cloud destination:

```sh
codex-security publish findings semgrep.json --to cloud \
  --provider semgrep --source-key ORGANIZATION/PROJECT/BRANCH \
  --source-repository-url https://github.com/example/project \
  --repository https://github.com/example/project --dry-run --format json
```

Keep the same source key for one organization, project and branch across runs.
`--source-repository-url` declares where the report came from; the importer checks
it against configured local Git remotes or the Cloud destination. Cloud requires
an authorized repository and support for the `semgrep` provider. Local SARIF
imports also check every original `versionControlProvenance.repositoryUri` on
accepted findings. Unknown Git hosts keep case-sensitive repository paths.

## Evidence and identity

CLI JSON preserves original severity, rule, CWE IDs, source range, snippets when
available and ignored state. SARIF retains its selected result and rule, including
trace and fix evidence. Its Critical and High ratings both become diagnostic
`error`, displayed here as High; prefer JSON when that distinction matters.
Original evidence stays in `source_data`, and source state stays separate from a
Codex assessment.

Cloud imports apply the service's evidence limits, including a maximum JSON
depth of 20. A deeply nested taint trace can exceed that bound and be excluded
with a reason in the Cloud preview. Local storage does not impose the Cloud
size or depth limits. Neither path flattens or truncates accepted traces.

Keep the supplied JSON `extra.fingerprint` or SARIF `matchBasedId/v1`
fingerprint. If a later report supplies the same fingerprint after the code
moves, importing it under the same repository and source key updates that record
with the new range; the raw fingerprint stays in `source_data`.

Community Edition may omit the fingerprint or emit `requires login`. The fallback
identity uses the rule, literal path and range. Moving such a finding creates a
second record, and the earlier record remains stored. The importer does not
infer that they are the same finding, merge them or delete the earlier record.
Read back both with `codex-security findings imported . --format json` before
selecting evidence for assessment. A current checkout does not establish the
report's revision or branch.

CLI JSON and SARIF imports accept SAST only. Select SAST rules or a Code-only CI
scan, since SARIF may omit enough product metadata to distinguish Secrets. Identifiable
Supply Chain and Secrets records are excluded. Reports with scan errors,
unsuccessful SARIF invocations or scan-error notifications are rejected. The
preview reports invalid findings and duplicate source identities before import.

SARIF supports direct artifact URIs and Semgrep's native `%SRCROOT%` marker without
a base definition. Native paths retain literal percent characters; direct URIs
are decoded once. Indexed artifacts and unresolved bases remain in original
evidence without mapped repository locations. CE records with these references
are excluded because they lack a usable identity. JSON scan-wide path inventories
and timing tables are omitted from individual findings. SARIF artifact inventories
are omitted when they are unrelated to the selected finding; required inventories
retain their original entries and indexes. Empty external-property reference
containers are accepted, while actual external file references are rejected.

For CLI and CI reports, SDK callers pass `{ sourceRepositoryUrl }` to `normalizeSemgrepFindings`,
`normalizeSemgrepSarif`, or `readSemgrepFindings`. When passing that normalized
output directly to `prepareNormalizedLocalImport`, supply the original SARIF
repository references in the third argument's `sourceRepositories`; the file
importer forwards them automatically. For an independently known GitHub custom
host, use `{ url, platform: "github" }` for its references. The Semgrep file reader
accepts native reports, not normalized JSON/JSONL exports.
See the [native output fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif).
