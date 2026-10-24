import { CodexSecurityError } from "../errors.js";

/** A rejected model decision; distinct from validator or transport failures. */
export class InvalidDeduplicationDecision extends CodexSecurityError {}
