# Import Trivy dependency findings

Enable vendor imports with `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`. Use a native schema-v2 JSON report from a Trivy repository or filesystem scan of one checkout. Plain JSON and gzip are supported. An existing CI artifact needs no scanner, database download, or Aqua account on the importing machine.

## Collect, preview, and import

To run a new scan, start in the repository root with Trivy and an accessible vulnerability database (or a populated cache):

```sh
trivy repo --scanners vuln --list-all-pkgs --format json --output ../trivy.json .
codex-security publish findings ../trivy.json --to local --repository . \
  --provider trivy --trivy-scan-root . --source-key example/project/main --dry-run --format json
```

`trivy fs` is also supported. `--list-all-pkgs` makes package declaration ranges available when the analyzer provides them. For a local-path report, supply the directory Trivy actually scanned, relative to the Git root: `--trivy-scan-root .` for the whole checkout or, for example, `--trivy-scan-root apps/web` for that subtree. A saved CI report cannot establish this offset from the scanner’s working directory. For a scan of a remote repository URL, the repository root is known and the flag is unnecessary.

Keep one stable source key per project and branch; do not put the scan ID or commit in it. Review the source, destination, package locations, and exclusions. Repeat without `--dry-run` to confirm, then use `codex-security findings imported . --format json` to read the stored evidence.

For Cloud, replace `--to local --repository .` with `--to cloud --repository URL_OR_ID`. This requires an authorized destination and a Cloud deployment that accepts the distinct `trivy` provider. The importer checks the report’s Git remote against the Cloud destination or a comparable local Git remote. On unknown Git hosts, supply the same remote spelling; different SSH users or paths can select different repositories. If the report has no network remote, or the local checkout has none to compare, independently verify the artifact's origin before confirming. A directory name is not proof of identity.

## Evidence and repeat imports

- Only language-package vulnerabilities from repository/filesystem reports are in scope. Image, Kubernetes/Operator, and SARIF reports are rejected. In a mixed native report, unsupported sections (such as OS packages, secrets, misconfigurations, and licenses) are reported as exclusions; their contents are not imported.
- The evidence identifies the advisory and package, takes the ecosystem from the package URL when available (otherwise the Trivy analyzer), and retains the manifest when known. It keeps the reported installed and fixed versions, severity, original vulnerability, and available Git revision and declaration locations. A missing line is not replaced with line 1.
- Reimporting the same report is unchanged. With the same source key, a change in commit, installed version, severity, or declaration line updates the same occurrence. Distinct manifests remain distinct. Ambiguous duplicate identities are reported as exclusions, not arbitrarily overwritten.
- `Status: fixed` describes upstream fix availability, not remediation in the checkout. Omission from a later report does not close the earlier record. Package detection does not establish exploitability or reachability: imported evidence remains `not_assessed`.
