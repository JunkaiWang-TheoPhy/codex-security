# Import Black Duck SCA repository vulnerabilities

Use `--provider blackduck` for vulnerable BOM components from **one Black Duck
SCA project version that represents one source repository**. Confirm that
mapping in your scan configuration first: the Black Duck project name, version
name, API host, and component download URL are not Git repository identities.
Do not import an aggregate product BOM, an image-only scan, license violations,
or a global advisory catalog as repository findings.

## Acquire a complete selection

Use a read-only Black Duck SCA token and your deployment's API documentation.
The project version's `vulnerable-components` relation resolves to
`/api/projects/{projectId}/versions/{versionId}/vulnerable-bom-components`.
Use the advertised BOM media type; the example uses
`application/vnd.blackducksoftware.bill-of-materials-6+json`. The official
Python package is `blackduck`, not the Detect scan launcher. Fetching this
collection does not start a scan. Treat the export as sensitive.

The following Python example uses the vendor client. Set `BLACKDUCK_URL` to
your trusted HTTPS deployment, `BLACKDUCK_TOKEN` in a private environment,
and `BLACKDUCK_PROJECT_ID` and `BLACKDUCK_VERSION_ID` to the two UUIDs.
Capture stdout to a private temporary file outside the checkout and rename it
only after successful exit. No new output is emitted on a failed page.

```python
import json
import os
from hashlib import sha256
from urllib.parse import urlsplit
from uuid import UUID
from blackduck import Client

base = os.environ["BLACKDUCK_URL"].rstrip("/")
parts = urlsplit(base)
if (parts.scheme != "https" or not parts.hostname or parts.username is not None
        or parts.password is not None or parts.query or parts.fragment):
    raise ValueError("Use your trusted HTTPS Black Duck URL")
project = UUID(os.environ["BLACKDUCK_PROJECT_ID"])
version = UUID(os.environ["BLACKDUCK_VERSION_ID"])
url = f"{base}/api/projects/{project}/versions/{version}/vulnerable-bom-components"
client = Client(base_url=base + "/", token=os.environ["BLACKDUCK_TOKEN"])
headers = {"Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json"}
items = []
seen = set()
total = None
while True:
    response = client.session.get(url, params={"offset": len(items), "limit": 250},
                                  headers=headers, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"Black Duck returned HTTP {response.status_code}; refusing partial export")
    page = response.json()
    batch, declared = page["items"], page["totalCount"]
    if not isinstance(batch, list) or type(declared) is not int or declared < 0:
        raise ValueError("Invalid Black Duck collection")
    if total is not None and declared != total:
        raise ValueError("Collection changed; retry the export")
    total = declared
    for row in batch:
        digest = sha256(json.dumps(row, sort_keys=True).encode()).digest()
        if digest in seen:
            raise ValueError("Repeated row; retry the export")
        seen.add(digest)
    items.extend(batch)
    if len(items) == total:
        break
    if not batch or len(items) > total:
        raise ValueError("Incomplete or inconsistent Black Duck collection")
print(json.dumps({"_meta": {"href": url}, "totalCount": total, "items": items}))
```

Keep the original rows. Never change `totalCount` to the number on the first
page or import the output of a failed fetch. Offset pagination is not an atomic
snapshot: if a BOM is changing during collection, export again after the scan
settles. A deliberately selected array of native rows is also supported when
each row identifies the same project version. An array says nothing about the
rest of the backlog.

## Preview and repeat

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings blackduck.json \
  --to local --repository ./project --provider blackduck \
  --source-repository-url https://github.com/example/project \
  --source-key blackduck/deployment-alias/project-id/version-id \
  --dry-run --format json
```

Review the source, destination and exclusions; remove `--dry-run` to import.
Use the same source key for subsequent exports from this deployment, project
and version. A key does not filter exports or prove the Git mapping. Local
imports require no Black Duck or Codex Cloud login. To publish, select an
authorized GitHub repository with `--to cloud` on a deployment that accepts
the `blackduck` source provider.

| Source evidence | What Codex Security tracks |
| --- | --- |
| Project version, component version/origin, advisory source and name | A package vulnerability occurrence. Different origins and advisories must not collapse into a CVE-only record. |
| Component name and version | The reported component and installed version. A Black Duck project version is not a Git commit. |
| Vendor severity and remediation status | Unassessed source evidence. A status such as `MITIGATED` is not a verified fix, a fixed package version, or a reason to delete the finding. |
| Matched-files link and BOM metadata | Raw evidence. The importer does not follow links, fabricate file/line locations, or infer reachability from BOM membership. |

Replaying an occurrence retains its identity; changed evidence updates it.
NVD and Black Duck advisories are not published by the target repository.
Package fields are typed; the original vendor record retains advisory source,
CWE and remediation status rather than assigning false advisory provenance.
Missing rows in a later export do not close findings. For large backlogs, scope
upstream to a single repository project version and keep the export for replay.
No licensed tenant or hosted MCP is needed to read a previously saved report.

References: [official Python REST client](https://github.com/blackducksoftware/hub-rest-api-python),
[vendor example of vulnerable BOM components](https://github.com/blackducksoftware/hub-client-go/blob/5f78f7257c00fe9cebabf1bf89a6fc36a4d1f095/hubapi/testdata/vulnerableBomComponents.json).
