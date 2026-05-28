-- Track every ingest run so the UI can surface freshness and operators
-- can spot a stuck source.
CREATE TABLE IF NOT EXISTS "sync_jobs" (
  "id"              bigserial PRIMARY KEY,
  "source"          text NOT NULL,                -- 'kev' | 'osv:npm' | 'epss' | ...
  "started_at"      timestamptz NOT NULL DEFAULT now(),
  "finished_at"     timestamptz,
  "status"          text NOT NULL DEFAULT 'running',  -- 'running' | 'success' | 'failed'
  "records_seen"    integer,
  "records_changed" integer,
  "error_message"   text
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_sync_jobs_source_started"
  ON "sync_jobs" ("source", "started_at" DESC);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "idx_sync_jobs_started"
  ON "sync_jobs" ("started_at" DESC);
