-- Create "access_tokens" table
CREATE TABLE "access_tokens" ("signature" text NOT NULL, "request_data" bytea NOT NULL, "request_id" text NOT NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("signature"));
-- Create index "idx_access_tokens_expires_at" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_expires_at" ON "access_tokens" ("expires_at");
-- Create index "idx_access_tokens_request_id" to table: "access_tokens"
CREATE INDEX "idx_access_tokens_request_id" ON "access_tokens" ("request_id");
-- Create "authorize_codes" table
CREATE TABLE "authorize_codes" ("code" text NOT NULL, "active" boolean NOT NULL DEFAULT true, "request_data" bytea NOT NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("code"));
-- Create index "idx_authorize_codes_expires_at" to table: "authorize_codes"
CREATE INDEX "idx_authorize_codes_expires_at" ON "authorize_codes" ("expires_at");
-- Create "blacklisted_jtis" table
CREATE TABLE "blacklisted_jtis" ("jti" text NOT NULL, "expires_at" timestamptz NOT NULL, PRIMARY KEY ("jti"));
-- Create index "idx_blacklisted_jtis_expires_at" to table: "blacklisted_jtis"
CREATE INDEX "idx_blacklisted_jtis_expires_at" ON "blacklisted_jtis" ("expires_at");
-- Create "clients" table
CREATE TABLE "clients" ("id" text NOT NULL, "secret" bytea NOT NULL, "redirect_uris" jsonb NOT NULL DEFAULT '[]', "grant_types" jsonb NOT NULL DEFAULT '[]', "response_types" jsonb NOT NULL DEFAULT '[]', "scopes" jsonb NOT NULL DEFAULT '[]', "public" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL DEFAULT now(), "updated_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("id"));
-- Create "oidc_sessions" table
CREATE TABLE "oidc_sessions" ("authorize_code" text NOT NULL, "request_data" bytea NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("authorize_code"));
-- Create "par_sessions" table
CREATE TABLE "par_sessions" ("request_uri" text NOT NULL, "request_data" bytea NOT NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("request_uri"));
-- Create index "idx_par_sessions_expires_at" to table: "par_sessions"
CREATE INDEX "idx_par_sessions_expires_at" ON "par_sessions" ("expires_at");
-- Create "pkce_sessions" table
CREATE TABLE "pkce_sessions" ("code" text NOT NULL, "request_data" bytea NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("code"));
-- Create "refresh_tokens" table
CREATE TABLE "refresh_tokens" ("signature" text NOT NULL, "active" boolean NOT NULL DEFAULT true, "request_data" bytea NOT NULL, "request_id" text NOT NULL, "access_token_signature" text NULL, "expires_at" timestamptz NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), PRIMARY KEY ("signature"));
-- Create index "idx_refresh_tokens_expires_at" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_expires_at" ON "refresh_tokens" ("expires_at");
-- Create index "idx_refresh_tokens_request_id" to table: "refresh_tokens"
CREATE INDEX "idx_refresh_tokens_request_id" ON "refresh_tokens" ("request_id");
