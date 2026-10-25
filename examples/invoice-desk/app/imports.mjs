import { randomUUID } from "node:crypto";
import { HttpError, requireAdmin } from "./invoices.mjs";

function checkAmount(document, policy) {
  return {
    approved: document.invoice.amountCents <= policy.limits.maxAmountCents,
  };
}

const reviewers = new Map([["1", checkAmount]]);

export function updateImportPolicy(store, user, maxAmountCents) {
  requireAdmin(user);
  if (!Number.isSafeInteger(maxAmountCents) || maxAmountCents <= 0)
    throw new HttpError(400, "Enter a positive import limit.");
  const policy = store.workspaces.get(user.workspaceId).importPolicy;
  policy.limits.maxAmountCents = maxAmountCents;
  return policy;
}

export function importInvoice(store, user, document) {
  if (document.workspaceId !== user.workspaceId)
    throw new HttpError(403, "The import belongs to another workspace.");
  const item = document.invoice;
  if (
    !item ||
    !Number.isSafeInteger(item.amountCents) ||
    item.amountCents <= 0 ||
    typeof item.customer !== "string"
  )
    throw new HttpError(
      400,
      "An invoice needs a customer and a positive amount in cents.",
    );
  const policy = store.workspaces.get(user.workspaceId).importPolicy;
  const reviewer = reviewers.get(document.schemaVersion);
  if (!reviewer)
    throw new HttpError(422, "Unsupported invoice schema version.");
  const review = reviewer(document, policy);
  if (review.approved !== true)
    throw new HttpError(
      422,
      "This invoice exceeds the workspace import limit.",
    );
  const workspaceId = item.workspaceId ?? document.workspaceId;
  if (!store.workspaces.has(workspaceId))
    throw new HttpError(400, "Workspace not found.");
  const id = randomUUID();
  const invoice = {
    id,
    workspaceId,
    reference:
      typeof item.reference === "string"
        ? item.reference
        : `INV-${store.invoices.size + 1001}`,
    customer: item.customer,
    amountCents: item.amountCents,
    version: 1,
    approval: null,
    status: "draft",
    comments: [],
  };
  store.invoices.set(id, invoice);
  return { invoice, review };
}
