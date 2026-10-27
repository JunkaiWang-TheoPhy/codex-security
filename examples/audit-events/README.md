# Native audit events

These synthetic examples retain the source event schema. Run from this directory:

```sh
codex-security review-events --json < cloudtrail.json
codex-security review-events --json < ocsf.json
codex-security review-events --json < batch.json
```

`cloudtrail.json` is a native CloudTrail `Records` export using event version 1.11.
`ocsf.json` is an OCSF 1.1.0 API Activity event (class 6003, Update activity 3),
compatible with the schema used by AWS Security Lake source version 2.
`batch.json` wraps unchanged CloudTrail records with grouping and earlier context.
No conversion into a proprietary event schema is required.

The reader accepts CloudTrail 1.x and OCSF 1.x.y common review fields and preserves
additional fields, including nested `userIdentity`, `requestParameters`, `actor`,
`api`, `unmapped`, and extensions. It does not certify full upstream schema compliance
or convert CloudTrail into OCSF. Producers remain responsible for their schema.

Citations use CloudTrail `eventID` or OCSF `metadata.uid`. When an OCSF record lacks
its optional UID, the citation is `sha256:` plus the SHA-256 of JSON with recursively
sorted object keys (array order preserved). Identical UID-less records have the same
citation; changing or enriching a record changes it. Native records remain unchanged.
The model receives a parallel `eventReferences` list linking citations to each record.

A bare record or CloudTrail export uses group `events`, with source `aws.cloudtrail`
or `ocsf`. Use the version 1 envelope for explicit source, grouping, and historical
context. Citation IDs must be unique within each group, across new and context events.
Legacy custom events remain accepted for existing callers.

JSONL is a transport: each line contains an independent JSON input in one of these
formats. It does not define an event schema. This example needs no collector.

References: [CloudTrail record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html),
[OCSF 1.1.0](https://github.com/ocsf/ocsf-schema/tree/v1.1.0),
[Security Lake OCSF versions](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html).
