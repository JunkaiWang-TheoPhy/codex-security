// Normalize authentication log lines into version 1 review batches.
import { once } from "node:events";
import { createInterface } from "node:readline";

const sessions = new Map();
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  const { source, session, id, timestamp, actor, action, outcome } =
    JSON.parse(line);
  const key = JSON.stringify([source, session]);
  const event = { id, timestamp, actor, action, outcome };
  const login = sessions.get(key);
  const batch = {
    schemaVersion: 1,
    source,
    serviceContext: "Deployment sessions normally read build artifacts.",
    groups: [
      {
        id: session,
        events: [event],
        contextEvents: login && login.id !== event.id ? [login] : [],
      },
    ],
  };
  if (!process.stdout.write(JSON.stringify(batch) + "\n"))
    await once(process.stdout, "drain");
  if (action === "AssumeRole") sessions.set(key, event);
  if (action === "EndSession") sessions.delete(key);
}
