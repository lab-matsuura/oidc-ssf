-- Create "ssf_streams" table
CREATE TABLE "ssf_streams" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "audience" text[] NOT NULL, "delivery_method" text NOT NULL DEFAULT 'urn:ietf:rfc:8935', "endpoint_url" text NOT NULL, "events_requested" text[] NOT NULL DEFAULT '{}', "events_delivered" text[] NOT NULL DEFAULT '{}', "status" text NOT NULL DEFAULT 'enabled', "status_reason" text NULL, "description" text NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "updated_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"), CONSTRAINT "ssf_streams_status_check" CHECK (status = ANY (ARRAY['enabled'::text, 'paused'::text, 'disabled'::text])));
-- Create index "idx_ssf_streams_created_at" to table: "ssf_streams"
CREATE INDEX "idx_ssf_streams_created_at" ON "ssf_streams" ("created_at");
-- Create index "idx_ssf_streams_status" to table: "ssf_streams"
CREATE INDEX "idx_ssf_streams_status" ON "ssf_streams" ("status");
-- Create "ssf_event_log" table
CREATE TABLE "ssf_event_log" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "stream_id" uuid NULL, "event_type" text NOT NULL, "jti" text NOT NULL, "subject_identifier" text NULL, "status" text NOT NULL DEFAULT 'queued', "attempts" integer NOT NULL DEFAULT 0, "last_error" text NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "sent_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "ssf_event_log_jti_key" UNIQUE ("jti"), CONSTRAINT "ssf_event_log_stream_id_fkey" FOREIGN KEY ("stream_id") REFERENCES "ssf_streams" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "ssf_event_log_status_check" CHECK (status = ANY (ARRAY['queued'::text, 'sent'::text, 'failed'::text, 'retry'::text])));
-- Create index "idx_ssf_event_log_created_at" to table: "ssf_event_log"
CREATE INDEX "idx_ssf_event_log_created_at" ON "ssf_event_log" ("created_at");
-- Create index "idx_ssf_event_log_jti" to table: "ssf_event_log"
CREATE INDEX "idx_ssf_event_log_jti" ON "ssf_event_log" ("jti");
-- Create index "idx_ssf_event_log_status" to table: "ssf_event_log"
CREATE INDEX "idx_ssf_event_log_status" ON "ssf_event_log" ("status");
-- Create index "idx_ssf_event_log_stream_id" to table: "ssf_event_log"
CREATE INDEX "idx_ssf_event_log_stream_id" ON "ssf_event_log" ("stream_id");
-- Create "ssf_stream_subjects" table
CREATE TABLE "ssf_stream_subjects" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "stream_id" uuid NOT NULL, "subject_format" text NOT NULL, "subject_identifier" text NOT NULL, "verified" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"), CONSTRAINT "ssf_stream_subjects_stream_id_subject_format_subject_identi_key" UNIQUE ("stream_id", "subject_format", "subject_identifier"), CONSTRAINT "ssf_stream_subjects_stream_id_fkey" FOREIGN KEY ("stream_id") REFERENCES "ssf_streams" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "idx_ssf_stream_subjects_stream_id" to table: "ssf_stream_subjects"
CREATE INDEX "idx_ssf_stream_subjects_stream_id" ON "ssf_stream_subjects" ("stream_id");
