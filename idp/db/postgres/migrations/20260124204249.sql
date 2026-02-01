-- Create "ssf_poll_events" table
CREATE TABLE "ssf_poll_events" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "stream_id" uuid NOT NULL, "jti" text NOT NULL, "set_token" text NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"), CONSTRAINT "ssf_poll_events_stream_id_jti_key" UNIQUE ("stream_id", "jti"), CONSTRAINT "ssf_poll_events_stream_id_fkey" FOREIGN KEY ("stream_id") REFERENCES "ssf_streams" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "idx_ssf_poll_events_created_at" to table: "ssf_poll_events"
CREATE INDEX "idx_ssf_poll_events_created_at" ON "ssf_poll_events" ("created_at");
-- Create index "idx_ssf_poll_events_stream_id" to table: "ssf_poll_events"
CREATE INDEX "idx_ssf_poll_events_stream_id" ON "ssf_poll_events" ("stream_id");
