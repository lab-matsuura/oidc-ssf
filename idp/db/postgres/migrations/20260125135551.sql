-- Create "ssf_events" table
CREATE TABLE "ssf_events" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "event_type" text NOT NULL, "subject_identifier" text NULL, "payload" jsonb NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"));
-- Create index "idx_ssf_events_created_at" to table: "ssf_events"
CREATE INDEX "idx_ssf_events_created_at" ON "ssf_events" ("created_at");
-- Create index "idx_ssf_events_subject" to table: "ssf_events"
CREATE INDEX "idx_ssf_events_subject" ON "ssf_events" ("subject_identifier");
-- Create index "idx_ssf_events_type" to table: "ssf_events"
CREATE INDEX "idx_ssf_events_type" ON "ssf_events" ("event_type");
-- Create "ssf_event_deliveries" table
CREATE TABLE "ssf_event_deliveries" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "event_id" uuid NOT NULL, "stream_id" uuid NOT NULL, "jti" text NOT NULL, "set_token" text NOT NULL, "status" text NOT NULL DEFAULT 'queued', "attempts" integer NOT NULL DEFAULT 0, "max_attempts" integer NOT NULL DEFAULT 10, "last_error" text NULL, "next_retry_at" timestamptz NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "sent_at" timestamptz NULL, "acked_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "ssf_event_deliveries_event_id_stream_id_key" UNIQUE ("event_id", "stream_id"), CONSTRAINT "ssf_event_deliveries_jti_key" UNIQUE ("jti"), CONSTRAINT "ssf_event_deliveries_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "ssf_events" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "ssf_event_deliveries_stream_id_fkey" FOREIGN KEY ("stream_id") REFERENCES "ssf_streams" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "ssf_event_deliveries_status_check" CHECK (status = ANY (ARRAY['queued'::text, 'sent'::text, 'failed'::text, 'retry'::text, 'acked'::text])));
-- Create index "idx_ssf_deliveries_event" to table: "ssf_event_deliveries"
CREATE INDEX "idx_ssf_deliveries_event" ON "ssf_event_deliveries" ("event_id");
-- Create index "idx_ssf_deliveries_jti" to table: "ssf_event_deliveries"
CREATE INDEX "idx_ssf_deliveries_jti" ON "ssf_event_deliveries" ("jti");
-- Create index "idx_ssf_deliveries_pending" to table: "ssf_event_deliveries"
CREATE INDEX "idx_ssf_deliveries_pending" ON "ssf_event_deliveries" ("status", "next_retry_at") WHERE (status = ANY (ARRAY['queued'::text, 'retry'::text]));
-- Create index "idx_ssf_deliveries_status" to table: "ssf_event_deliveries"
CREATE INDEX "idx_ssf_deliveries_status" ON "ssf_event_deliveries" ("status");
-- Create index "idx_ssf_deliveries_stream" to table: "ssf_event_deliveries"
CREATE INDEX "idx_ssf_deliveries_stream" ON "ssf_event_deliveries" ("stream_id");
-- Drop "ssf_event_log" table
DROP TABLE "ssf_event_log";
-- Drop "ssf_poll_events" table
DROP TABLE "ssf_poll_events";
