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
Request **BOM-6**: `application/vnd.blackducksoftware.bill-of-materials-6+json`.
Do not substitute BOM-8 or a generic inventory: those row shapes are not
supported. If the deployment cannot serve BOM-6, stop rather than treating
excluded rows as an empty vulnerability backlog. The official
Python package is `blackduck`, not the Detect scan launcher. Fetching this
collection does not start a scan. Treat the export as sensitive.

The following Python example uses the vendor client. Set `BLACKDUCK_URL` to
your trusted HTTPS deployment, `BLACKDUCK_TOKEN` in a private environment,
and `BLACKDUCK_PROJECT_ID` and `BLACKDUCK_VERSION_ID` to the two UUIDs.
Install the vendor client in a trusted virtual environment outside the checkout.
Save the example as a private script there and run it with the environment's
interpreter in isolated mode, for example
`/path/to/venv/bin/python -I /private/path/export.py`. This keeps checkout
modules and `PYTHONPATH` off the import path while the token is available.
Capture stdout to a private temporary file outside the checkout and rename it
only after success.

```python
import json
import os
from hashlib import sha256
from urllib.parse import parse_qs, urlsplit
from uuid import UUID
from blackduck import Client

base = os.environ["BLACKDUCK_URL"].rstrip("/")
parts = urlsplit(base)
if (parts.scheme != "https" or not parts.hostname or parts.username is not None
        or parts.password is not None or parts.query or parts.fragment):
    raise ValueError("Use your trusted HTTPS Black Duck URL")
project = UUID(os.environ["BLACKDUCK_PROJECT_ID"])
version = UUID(os.environ["BLACKDUCK_VERSION_ID"])
collection = f"{project}/versions/{version}/vulnerable-bom-components"
url = f"{base}/api/projects/{collection}"
paths = {f"{parts.path}/api/{relation}/{collection}" for relation in ("projects", "project")}

def authority(url):
    return url.netloc.lower().removesuffix(":443")

client = Client(base_url=base + "/", token=os.environ["BLACKDUCK_TOKEN"])
client.session.max_redirects = 0
media_type = "application/vnd.blackducksoftware.bill-of-materials-6+json"
items = []
seen = set()
total = None
while True:
    offset = len(items)
    response = client.session.get(url, params={"offset": offset, "limit": 250},
                                  headers={"Accept": media_type}, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"Black Duck returned HTTP {response.status_code}; refusing partial export")
    received_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if received_type != media_type:
        raise ValueError("Expected a BOM-6 response")
    page = response.json()
    href = urlsplit(page["_meta"]["href"])
    if (href.scheme != "https" or authority(href) != authority(parts)
            or href.fragment or href.path not in paths):
        raise ValueError("Page identifies a different Black Duck collection")
    query = parse_qs(href.query, keep_blank_values=True)
    if "offset" in query and query["offset"] != [str(offset)]:
        raise ValueError("Page identifies a different or ambiguous offset")
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

Use the canonical HTTPS deployment URL, not a redirector. The vendor client
exchanges its API token for a bearer token before reading the collection.
Disabling redirects on the entire session also protects that authentication
exchange; disabling them on only the collection GET is not sufficient.

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

| Source evidence                                                     | What Codex Security tracks                                                                                                                                 |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Project version, component version/origin, advisory source and name | A package vulnerability occurrence. Different origins and advisories must not collapse into a CVE-only record.                                             |
| Component origin and native package coordinates                     | A supported package URL or origin coordinate supplies the package identity. With no supported coordinate, display metadata stays in the title and raw row. |
| Advisory identifiers                                                | The reported advisory name and its distinct `relatedVulnerability` alias when present. The raw row retains the advisory source.                            |
| Vendor severity and remediation status                              | Unassessed source evidence. A status such as `MITIGATED` is not a verified fix, a fixed package version, or a reason to delete the finding.                |
| Matched-files link and BOM metadata                                 | Raw evidence. The importer does not follow links, fabricate file/line locations, or infer reachability from BOM membership.                                |

Replaying an occurrence retains its identity and updates changed evidence.
The original vendor row retains the CWE and remediation status. The project
version identifies the BOM and supplies no Git commit evidence.
Missing rows in a later export do not close findings. For large backlogs, scope
upstream to a single repository project version and keep the export for replay.
No licensed tenant or hosted MCP is needed to read a previously saved report.

References: [official Python REST client](https://github.com/blackducksoftware/hub-rest-api-python),
[vendor example of vulnerable BOM components](https://github.com/blackducksoftware/hub-client-go/blob/5f78f7257c00fe9cebabf1bf89a6fc36a4d1f095/hubapi/testdata/vulnerableBomComponents.json).
