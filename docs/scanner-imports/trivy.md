# Import Trivy dependency findings

Import an existing Trivy schema-v2 JSON report for one checkout. Use a report saved by CI or produced in an isolated scanner job with only approved inputs and no credentials. Both plain JSON and gzip are supported. The import requires no Trivy installation, vulnerability database, or Aqua account.

## Preview and import

Set `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`. Preview the report against the checkout it describes.

```sh
checkout=/absolute/path/to/project
codex-security publish findings /path/to/reports/trivy.json --to local --repository "$checkout" \
  --provider trivy --trivy-scan-root . --source-key example/project/main --dry-run --format json
```

The importer infers `.` only when the report names a remote repository and its Git metadata confirms that repository. If a target such as `HTTPS://example.com/org/repo` differs from the recorded Git URL only in the case of its HTTP scheme, set the scan root explicitly. A local scan may emit the same label. For other scans without a corroborated remote, set `--trivy-scan-root` to the scanned directory relative to the Git root. Use `.` for the whole checkout or `apps/web` for a subtree on any platform. In this argument, a backslash is a path separator on Windows and a literal filename character on POSIX.

Trivy can remove the SSH username when it saves a repository URL. If the report only names `ssh://host/path`, it can be inspected with an explicit scan root, but it lacks the username needed to bind an import. Verify the checkout uses an explicit SCP-style `git@host:path` or HTTPS remote for the intended repository, then regenerate the report from that checkout.

A saved Git origin such as `r:org/repo.git` can name either a Windows drive-relative path or a one-letter SSH server. Supply the scan root if this is the only origin. For a one-letter SSH server, configure the remote as `git@r:org/repo.git`. Trivy preserves this spelling in the report.

Use a stable source key per project and branch across commits and scans. Check the source, destination, package locations, and exclusions in the preview. Repeat without `--dry-run` to confirm. Read the stored evidence with `codex-security findings imported "$checkout" --format json`.

For Cloud, replace `--to local --repository "$checkout"` with `--to cloud --repository URL_OR_ID`. You need access to the destination and a Cloud deployment that accepts the `trivy` provider. The importer compares the report’s Git remote with the destination when both are available. On unknown Git hosts, use the same remote spelling because distinct SSH users or paths can select different repositories. The importer rejects conflicting repository URLs. If either side lacks a comparable remote, verify the report’s origin before confirming.

## Evidence and repeat imports

The importer accepts language-package vulnerabilities in repository and filesystem reports. It rejects image, Kubernetes/Operator, and SARIF reports. In mixed reports, it lists unsupported sections such as OS packages, secrets, misconfigurations, and licenses as exclusions.

Each finding retains the original vulnerability, advisory, package, reported versions and severity. The original `FixedVersion` field preserves the vendor’s exact expression. The ecosystem comes from the package URL when present and otherwise from the Trivy analyzer. The importer preserves the manifest and declaration lines when available. Trivy can report the checkout’s HEAD while scanning uncommitted files. The reported commit stays in `source_data.report.Metadata.Commit`, and `code_revision` remains unknown.

The importer uses Trivy’s v0.36.0 path convention. It treats `/` as a directory separator and preserves backslashes as literal filename characters. If an older Windows report uses backslashes as separators, regenerate it from the same checkout and scan root with Trivy v0.36.0 or later before importing. [Trivy v0.36.0 filesystem walker](https://github.com/aquasecurity/trivy/blob/4813cf5cfdaf22d3caf8ca2a2cc89448a5ef994f/pkg/fanal/walker/fs.go#L32-L37)

Trivy can report the same package path for a JAR inside a WAR file and a JAR inside an unpacked directory named `site.war`. The importer retains the ambiguous path in the original evidence and occurrence identity and omits it from file locations.

With the same source key and identifying paths, a change in version, severity, commit, or declaration line updates the existing occurrence. Replaying identical evidence leaves it unchanged. A different manifest or package path, including a versioned JAR filename, identifies a new occurrence. If several records have the same identity, the importer excludes all of them.

If you tested an earlier development build of this importer, finish any interrupted Cloud upload with the build that created it before switching builds. The saved request includes that build’s evidence format.

A Trivy status of `fixed` means an upstream fix is available. Imported evidence starts as `not_assessed`. Omitting an occurrence from a later report leaves its earlier record open.
