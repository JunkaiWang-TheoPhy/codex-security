import { z } from "zod";

const workerOutcomeSchema = z.strictObject({
  status: z.enum(["completed", "blocked"]),
  reason: z.string(),
});

export type CodexWorkerOutcome = z.infer<typeof workerOutcomeSchema>;
export const workerOutcomeOutputSchema = z.toJSONSchema(workerOutcomeSchema);

export const workerOutcomeInstructions = [
  "Return a final JSON worker outcome with status and reason.",
  'Use status "completed" only after the source-backed audit finishes and its final draft is accepted. A verified scope with no applicable source may complete with no findings.',
  'If source access, execution, or another prerequisite prevents the audit, preserve any progress with complete: false and return status "blocked" with the actual reason. Do not submit a complete draft to stand in for blocked analysis.',
  "An ended turn, a saved artifact, or zero findings alone does not establish completed review.",
].join("\n");

export function parseWorkerOutcome(response: string): CodexWorkerOutcome {
  try {
    const outcome = workerOutcomeSchema.parse(JSON.parse(response));
    if (outcome.status === "blocked" && !outcome.reason.trim())
      throw new Error("A blocked outcome must include its reason.");
    return outcome;
  } catch (cause) {
    throw new Error("Codex worker outcome is missing or invalid.", { cause });
  }
}
