# Import Veracode Static Analysis policy findings

Use `--provider veracode` for the **Findings API** backlog of one Veracode
application mapped to one source repository. This importer handles
`scan_type=STATIC` in the application context. A Veracode application may
aggregate multiple repositories or binary modules: do not bind that aggregate
to a single checkout. Pipeline Scan JSON, sandboxes, SCA, DAST, policy pass/fail
summaries and the findings converter's SARIF output are not this format.

## Export unmodified Findings API pages

With read access to the selected application and the Results API, configure
your vendor-supported HMAC client and the API hostname for your region. The
example uses HTTPie with the Veracode authentication plugin and `jq`. Choose
the exact application GUID; a name search that picks the first match can select
a different application. The command reads existing findings and never starts
a scan. Treat the output as sensitive and keep it outside the checkout.

```bash
set -eu
umask 077
out=$(mktemp -d)
: "${VERACODE_APPLICATION_GUID:?Set the intended application GUID}"
api=https://api.veracode.com
guid=$(jq -ner --arg guid "$VERACODE_APPLICATION_GUID" '$guid | ascii_downcase |
  select(test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))')
application="$api/appsec/v1/applications/$guid"
page=0
while :; do
  http --ignore-stdin --check-status --body --timeout 20 --auth-type veracode_hmac GET \
    "$api/appsec/v2/applications/$guid/findings" \
    scan_type==STATIC page=="$page" size==100 > "$out/page.tmp"
  jq -e --arg app "$application" --argjson n "$page" \
    '._links.application.href == $app and
     .page.number == $n and (.page.total_pages | type == "number") and
     ((._embedded.findings | type == "array") or
      ((has("_embedded") | not) and $n == 0 and .page.total_elements == 0 and
       (.page.total_pages == 0 or .page.total_pages == 1)))' "$out/page.tmp" >/dev/null
  jq -c '.' "$out/page.tmp" >> "$out/pages.stream"
  pages=$(jq -r '.page.total_pages' "$out/page.tmp")
  page=$((page + 1))
  [ "$page" -lt "$pages" ] || break
done
jq -s '.' "$out/pages.stream" > "$out/policy-findings.json"
```

Do not substitute a single first page, follow credentialed links on an unknown
host, or adjust the native total. Keep each page intact. Policy-violating-only,
open-only, and sandbox selections are not the whole application backlog. When
exporting a deliberate filter such as `violates_policy=true`, document its
scope and keep it consistent across pages. Recollect if the backlog changes
during pagination; arithmetic alone cannot prove a transactional snapshot.

## Preview and import

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/policy-findings.json" \
  --to local --repository ./project --provider veracode \
  --source-repository-url https://github.com/example/project \
  --source-key veracode/region/application-guid/static \
  --dry-run --format json
```

Review the destination, count and exclusions. Remove `--dry-run` to import.
Use the same source key for later exports from the same application and
context; an application GUID is not evidence of a Git URL. For Cloud use an
authorized GitHub repository and a deployment that accepts provider `veracode`.

| Veracode evidence                              | What Codex Security tracks                                                                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| API origin, application/context and `issue_id` | A stable policy flaw occurrence. Build number, line, CWE and the separate Pipeline flaw ID are not its identity.                      |
| Native severity, CWE and flaw description      | SAST evidence, preserving the original numeric severity, description and status in the raw record.                                    |
| Static analysis path, line and module          | Reported evidence, not proof that a similarly named file exists in the checkout. No fabricated column or Git commit.                  |
| Finding status, mitigation and resolution      | Upstream workflow history, not a Codex assessment. Replaying an update does not mark a fix verified; omissions do not delete records. |

References: [Veracode Findings API](https://docs.veracode.com/r/c_findings_v2_intro),
[vendor-supported policy and Pipeline conversion examples](https://github.com/veracode/veracode-pipeline-scan-results-to-sarif).
