// Optional history wrapper for the synthetic native CloudTrail fixture.
// Records are preserved, not translated into a custom event schema.
import { once } from "node:events";
import { createInterface } from "node:readline";

const sessions = new Map();
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  const event = JSON.parse(line);
  const session =
    event.responseElements?.assumedRoleUser?.arn ?? event.userIdentity.arn;
  const source = "aws.cloudtrail";
  const login = sessions.get(session);
  const batch = {
    schemaVersion: 1,
    source,
    serviceContext: "Deployment sessions normally read build artifacts.",
    groups: [
      {
        id: session,
        events: [event],
        contextEvents: login && login.eventID !== event.eventID ? [login] : [],
      },
    ],
  };
  if (!process.stdout.write(JSON.stringify(batch) + "\n"))
    await once(process.stdout, "drain");
  if (event.eventName === "AssumeRole" && !event.errorCode)
    sessions.set(session, event);
}
