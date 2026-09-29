DROP INDEX `mailbox_domain_local_uq`;--> statement-breakpoint
CREATE UNIQUE INDEX `mailbox_domain_local_uq` ON `mailbox` (`domain_id`,`local_part`) WHERE "mailbox"."pending_purge" IS NOT 'delete';