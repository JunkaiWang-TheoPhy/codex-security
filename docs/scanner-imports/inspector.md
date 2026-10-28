# Import Amazon Inspector repository vulnerabilities

Use `--provider inspector` to import package and code vulnerabilities from one
**Amazon Inspector Code Security** repository. The importer excludes EC2, ECR,
Lambda and network findings.

## Export one repository

Confirm that Inspector covers the repository in the intended AWS account and
Region. Use a read-only principal with `inspector2:ListFindings`. In this
GitHub example, replace the account and repository resource IDs with values
from Inspector coverage. The resource ID distinguishes integrations with the
same project name. Save the export outside the checkout because it can contain
source paths and account or integration identifiers.

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

Start at the first page and leave automatic pagination enabled. Omit
`--starting-token`, `--no-paginate`, `--max-items` and any `--query` that
drops continuation information. The importer rejects responses with a token,
but the final page alone has no token. Prefer the resource ID over a project
name that can change. Additional filters such as status limit which findings
the export includes.

## Preview and import

Inspector can identify a repository by an opaque project ARN and a name such as
`example/project`. That name can exist on several Git hosts. For these exports,
maintain a JSON map keyed by the full Inspector project ARN. Verify each URL
against the SCM repository connected to that project during integration setup.
For local imports, keep the map outside the selected repository and any checkout
containing the repository or export. You can store the map in a separate
configuration checkout. For Cloud publication, keep the map under operator
control outside all Git checkouts. The CLI checks the map path, including its
directory links, for checkout markers and recognizable Git metadata. It
recognizes headless common storage when a `config` file accompanies the
`objects` and `refs` directories. Links in those positions also count.

```json
{
  "arn:aws:inspector2:us-east-1:123456789012:codesecurity-integration/11111111-1111-4111-8111-111111111111/project-22222222-2222-4222-8222-222222222222": "https://github.com/example/project"
}
```

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/inspector.json" \
  --to local --repository ./project --provider inspector \
  --source-repository-url https://github.com/example/project \
  --inspector-project-map /trusted/inspector-projects.json \
  --source-key inspector/account-alias/us-east-1/example/project \
  --dry-run --format json
```

Check the selected repository, finding IDs and exclusions, then remove
`--dry-run` to import. Reuse the source key for exports from the same account,
Region and repository, even if you change the filters. Local import requires
no AWS credentials or Codex Cloud login. For Cloud, use `--to cloud` with an
authorized GitHub repository and a deployment that accepts `inspector`. Use
`--to local` for self-managed GitLab.

When you supply `--inspector-project-map`, the selected project must have an
entry. Its URL must agree with the declared source, any native URL, and the
Cloud destination or configured local Git remote. On custom hosts, use the path casing in the map
for the declared source and any native repository URL. Cloud matches its
authorized GitHub or GitHub Enterprise destination using GitHub’s
case-insensitive owner and repository names. Supply the mapping again when
replaying an import or resuming a pending Cloud submission. SDK callers can pass the
same bindings in the `inspectorProjectMap` option of type
`ReadonlyMap<string, string>` when preparing a raw or normalized Inspector
import. Other providers reject this option. Normalized imports retain their
selected provider even when a source ID happens to match an Inspector ARN.
For a normalized local import with a home-relative SSH repository path, the SDK
compares explicit login names. If either URL omits the login, verify that both
refer to the same account. The SDK does not resolve SSH configuration.

You can omit the map for exports that already contain a matching native
repository URL. Rows in the same verified project can supply the native URL
and provider for rows that omit them. On a custom GitHub Enterprise host,
Cloud needs at least one row identifying the provider as GitHub. Keep each
export scoped to one project.

## What gets tracked

| Inspector evidence                       | Codex Security interpretation                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Finding ARN and repository resource      | A stable source occurrence, not a global CVE ID. An explicit repository URL is required; do not use it to relabel a different project's results.                    |
| Repository `PACKAGE_VULNERABILITY`       | Advisory and reported vulnerable packages, installed versions, and fixed versions when supplied. An absent fixed version is unknown.                                |
| Repository `CODE_VULNERABILITY`          | Code finding with reported detector and source location when available; an unsafe or absent source path is not a checkout location.                                 |
| Severity, status, and remediation        | Source evidence. `UNTRIAGED` is not low severity. `CLOSED` and `SUPPRESSED` do not mean Codex verified a fix or assessed the finding.                               |
| Coverage, inventory, and other resources | Not vulnerability occurrences in a source repository. No commit is inferred from a default branch, scan date, or the latest commit in a separate coverage response. |

An NVD or other vendor advisory is not a disclosure published by the selected
repository. Package fields and advisory identifiers use the shared schema; the
upstream advisory source, repository, and workflow status stay in the native
evidence. A generic Inspector code finding is not automatically tagged SAST
or IaC when the report does not distinguish them.

Reimporting an ARN under the same source key updates that occurrence. Findings
omitted from a later selection are not deleted or marked fixed. For large
backlogs, use nonoverlapping filters and keep the original export. An empty
export leaves local history unchanged. Cloud skips publication when a
selection is empty or all its findings are excluded.

References: [AWS CLI: inspector2 list-findings](https://docs.aws.amazon.com/cli/latest/reference/inspector2/list-findings.html),
[ListFindings API](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html),
[code repository details](https://docs.aws.amazon.com/inspector/v2/APIReference/API_CodeRepositoryDetails.html).
