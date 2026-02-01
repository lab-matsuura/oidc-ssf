-- Modify "ssf_event_log" table
ALTER TABLE "ssf_event_log" ADD COLUMN "payload" jsonb NULL, ADD COLUMN "max_attempts" integer NOT NULL DEFAULT 5, ADD COLUMN "next_retry_at" timestamptz NULL;
-- Create index "idx_ssf_event_log_pending" to table: "ssf_event_log"
CREATE INDEX "idx_ssf_event_log_pending" ON "ssf_event_log" ("status", "next_retry_at") WHERE (status = ANY (ARRAY['queued'::text, 'retry'::text]));
-- Modify "ssf_streams" table
ALTER TABLE "ssf_streams" ADD COLUMN "client_id" text NULL, ADD COLUMN "authorization_header" text NULL;
