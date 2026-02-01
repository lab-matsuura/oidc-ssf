-- Create "idp_sessions" table
CREATE TABLE "idp_sessions" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "expires_at" timestamptz NOT NULL, "revoked_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "idp_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "idx_idp_sessions_user_id" to table: "idp_sessions"
CREATE INDEX "idx_idp_sessions_user_id" ON "idp_sessions" ("user_id");
