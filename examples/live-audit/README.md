# Live native audit event review

Run from the repository root with Node.js and the CLI installed. Native CloudTrail
records or OCSF records can be streamed directly as JSONL, with no collector or
schema conversion:

```sh
codex-security review-events --live -c examples/live-audit/monitor.yaml < examples/live-audit/cloudtrail.jsonl
codex-security review-events --live -c examples/live-audit/monitor.yaml < examples/live-audit/ocsf.jsonl
```

JSONL means one JSON input per line; each input retains its security event schema.
The fixtures are synthetic CloudTrail 1.11 and OCSF 1.1.0 records. A CloudTrail
`Records` export or version 1 batch can also occupy a line. Batch size counts input
lines, not events inside an export. Direct inputs use source `aws.cloudtrail` or
`ocsf` and group `events`; switching sources flushes the current window.

For context across windows, the existing optional wrapper example retains a role
assumption and supplies it alongside subsequent native events:

```sh
node examples/live-audit/collect.mjs < examples/live-audit/cloudtrail.jsonl |
  codex-security review-events --live -c examples/live-audit/monitor.yaml
```

The wrapper groups this fixture by the assumed-role ARN from the `AssumeRole`
response or the subsequent event's `userIdentity.arn`. It retains unchanged records,
including request and response details. The grant in the second window can cite the
role assumption in the first. This small example keeps history in memory until exit;
a durable producer owns expiry, history persistence, and checkpointing.

The monitor combines events by native citation ID. Repeated identical records are
deduplicated, new records take precedence over identical context, and conflicting
records with the same citation ID fail the window. See [native IDs and supported
versions](../audit-events/README.md). Historical context is supplied explicitly;
the monitor does not retain prior windows automatically.

Direct Codex review can use an existing ChatGPT sign-in. To screen each group before
full review, set `screen_with_decisions: true` and export `OPENAI_API_KEY`. ChatGPT
sign-in alone cannot authenticate Decisions. Save successful stdout results before
advancing a durable source cursor.
