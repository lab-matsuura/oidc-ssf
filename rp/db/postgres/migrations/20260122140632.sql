-- Create "ssf_config" table
CREATE TABLE "ssf_config" ("id" integer NOT NULL DEFAULT 1, "stream_id" text NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "updated_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"), CONSTRAINT "single_row" CHECK (id = 1));
-- Create "users" table
CREATE TABLE "users" ("sub" text NOT NULL, "email" text NULL, "name" text NULL, "role" text NOT NULL DEFAULT 'user', "created_at" timestamptz NOT NULL DEFAULT now(), "updated_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("sub"));
-- Create index "idx_users_email" to table: "users"
CREATE INDEX "idx_users_email" ON "users" ("email");
-- Create index "idx_users_role" to table: "users"
CREATE INDEX "idx_users_role" ON "users" ("role");
-- Create "sessions" table
CREATE TABLE "sessions" ("id" text NOT NULL, "user_sub" text NOT NULL, "access_token" text NOT NULL, "id_token" text NOT NULL, "refresh_token" text NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"), CONSTRAINT "sessions_user_sub_fkey" FOREIGN KEY ("user_sub") REFERENCES "users" ("sub") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "idx_sessions_expires_at" to table: "sessions"
CREATE INDEX "idx_sessions_expires_at" ON "sessions" ("expires_at");
-- Create index "idx_sessions_user_sub" to table: "sessions"
CREATE INDEX "idx_sessions_user_sub" ON "sessions" ("user_sub");
