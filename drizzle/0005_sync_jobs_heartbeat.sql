-- Heartbeat column for reaper logic. Reaper previously keyed off
-- started_at > 2h, which mis-fires two ways:
--   (1) legitimate ingests that take > 2h get killed mid-run
--   (2) ingests that hang silently before the first progress() call
--       (e.g. download stuck) wait the full 2h before getting reaped
-- Heartbeat is updated on startJob INSERT and on every progress() flush,
-- so reaper can use a 5-minute no-heartbeat threshold safely.
ALTER TABLE "sync_jobs" ADD COLUMN IF NOT EXISTS "last_heartbeat_at" timestamptz;
--> statement-breakpoint
-- Backfill so existing 'running' rows have a sane heartbeat baseline.
UPDATE "sync_jobs" SET "last_heartbeat_at" = COALESCE("finished_at", "started_at")
  WHERE "last_heartbeat_at" IS NULL;
