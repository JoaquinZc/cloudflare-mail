import type { DB } from "@cfmail/db";
import { mailbox } from "@cfmail/db/schema";
import { and, eq } from "drizzle-orm";
import { mailboxNotDeletePending } from "./permissions.ts";

// Flag a mailbox for background purge. The cron's purgePendingMailboxes drains
// its threads (and their blobs) in bounded batches, then finalizes: "empty"
// clears the flag, "delete" drops the mailbox row. Every mailbox deletion goes
// through this — a synchronous cascade-delete of a large mailbox exceeds D1's
// per-statement limits and loads every blob key into memory. A delete-pending
// mailbox reads as gone immediately (mailboxNotDeletePending / resolveAccess).
// "delete" is terminal: it drops the row out of the address index, so letting an
// "empty" flip it back could collide with a mailbox re-created at that address.
export async function markMailboxPurge(
  db: DB,
  mailboxId: string,
  mode: "empty" | "delete",
): Promise<void> {
  await db
    .update(mailbox)
    .set({ pendingPurge: mode })
    .where(and(eq(mailbox.id, mailboxId), mailboxNotDeletePending));
}
