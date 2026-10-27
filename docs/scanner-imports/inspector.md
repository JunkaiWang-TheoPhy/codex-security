# Import Amazon Inspector repository vulnerabilities

Use `--provider inspector` for findings from **Amazon Inspector Code Security**.
It is not an importer for the EC2, ECR, or Lambda vulnerability inventory. A
CVE on a running instance, an image tag matching a repository name, or a Lambda
code finding does not establish that a source checkout contains vulnerable code.

## Export one repository

First confirm that Inspector Code Security covers the repository in the intended
AWS account and Region. Use a read-only principal with `inspector2:ListFindings`.
The following example is for GitHub; substitute the account ID and repository
resource ID from Inspector coverage. The resource ID
distinguishes integrations that report the same project name. Keep the raw JSON
outside the checkout. It may include source
paths, account and integration identifiers, and other sensitive evidence.

```bash
set -eu
umask 077
export AWS_REGION=us-east-1
out=$(mktemp -d)
AWS_PAGER="" aws inspector2 list-findings --region "$AWS_REGION" \
  --filter-criteria '{
    "awsAccountId":[{"comparison":"EQUALS","value":"ACCOUNT_ID"}],
    "resourceType":[{"comparison":"EQUALS","value":"CODE_REPOSITORY"}],
    "resourceId":[{"comparison":"EQUALS","value":"REPOSITORY_RESOURCE_ID"}],
    "codeRepositoryProviderType":[{"comparison":"EQUALS","value":"GITHUB"}]
  }' --output json > "$out/inspector.json.tmp"
mv "$out/inspector.json.tmp" "$out/inspector.json"
```

Start at the first page and leave automatic pagination enabled. Do not use
`--starting-token`, `--no-paginate`, `--max-items`, or a `--query` that drops
continuation information. A response carrying a continuation token is
incomplete; a response **without** a token can still be just the final page.
The optional project-name filter is mutable after a rename. A narrower, intentional selection
(for example, just active findings) is not a complete account history.

## Preview and import

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/inspector.json" \
  --to local --repository ./project --provider inspector \
  --source-repository-url https://github.com/example/project \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

Check the selected repository, finding IDs and exclusions. Remove `--dry-run`
to approve the import. Keep the source key stable across repeated exports from
the same account, Region and repository; it is a namespace, not a filter. Local
import requires no AWS credentials or Codex Cloud login. For Cloud, use
`--to cloud` and an authorized GitHub repository as `--repository`; the
deployment must accept the `inspector` provider. A self-managed GitLab
repository is not a substitute for a GitHub Cloud destination.

Inspector must supply a verifiable repository claim: a bare project name or
opaque resource ID alone is not enough. A namespace path does not prove an
GitHub Enterprise tenant or Server hostname; include a native URL binding
that agrees with the selected host. Reject a mixed repository or integration
export rather than selecting a repository by its display name. For delegated
accounts, the account and resource ID filters in the example matter.

## What gets tracked

| Inspector evidence | Codex Security interpretation |
| --- | --- |
| Finding ARN and repository resource | A stable source occurrence, not a global CVE ID. An explicit repository URL is required; do not use it to relabel a different project's results. |
| Repository `PACKAGE_VULNERABILITY` | Advisory and reported vulnerable packages, installed versions, and fixed versions when supplied. An absent fixed version is unknown. |
| Repository `CODE_VULNERABILITY` | Code finding with reported detector and source location when available; an unsafe or absent source path is not a checkout location. |
| Severity, status, and remediation | Source evidence. `UNTRIAGED` is not low severity. `CLOSED` and `SUPPRESSED` do not mean Codex verified a fix or assessed the finding. |
| Coverage, inventory, and other resources | Not vulnerability occurrences in a source repository. No commit is inferred from a default branch, scan date, or the latest commit in a separate coverage response. |

An NVD or other vendor advisory is not a disclosure published by the selected
repository. Package fields and advisory identifiers use the shared schema; the
upstream advisory source, repository, and workflow status stay in the native
evidence. A generic Inspector code finding is not automatically tagged SAST
or IaC when the report does not distinguish them.

Reimporting an ARN under the same source key updates that occurrence. Findings
omitted from a later selection are not deleted or marked fixed. For large
backlogs, use nonoverlapping source filters, keep the original export, and
review the preview before publication. Keep the same source key for selections
from the same source; changing it creates a separate history.
An empty local export is a no-op. Cloud does not submit a request for an
empty or entirely excluded selection.

References: [AWS CLI: inspector2 list-findings](https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html),
[ListFindings API](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html),
[code repository details](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeRepositoryDetails.html).
