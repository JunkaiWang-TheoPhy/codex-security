# Live authentication log review

Run from the repository root with Node.js and the CLI installed. The fixture emits two review windows. The example uses direct Codex review by default and can use your existing ChatGPT sign-in to Codex.

```sh
node examples/live-audit/collect.mjs < examples/live-audit/auth.jsonl |
  codex-security review-events --live -c examples/live-audit/monitor.yaml
```

To follow an append-only authentication log on Unix, replace the fixture with a producer.

```sh
tail -n 0 -F auth.jsonl | node examples/live-audit/collect.mjs |
  codex-security review-events --live -c examples/live-audit/monitor.yaml
```

Each line carries a source, session ID, stable event ID, timestamp, actor, action, and outcome. The collector emits one normalized record per input line. It retains the most recent role assumption for each open source/session pair as historical evidence until an `EndSession` event. The grant in the second window can therefore cite the login in the first. Restarting this example clears its in-memory history.

The monitor owns the count and time thresholds. To screen each distinct group before full review, set `screen_with_decisions: true` and export an OpenAI API key as `OPENAI_API_KEY`. A ChatGPT sign-in to Codex alone cannot authenticate Decisions screening.

The monitor emits review results on stdout. A pager or durable collector can consume these results and advance its cursor after saving a window.
