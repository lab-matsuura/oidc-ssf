-- Create "users" table
CREATE TABLE "users" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "username" text NOT NULL, "email" text NOT NULL, "email_verified" boolean NOT NULL DEFAULT false, "password_hash" bytea NULL, "display_name" text NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "updated_at" timestamptz NOT NULL DEFAULT now(), "last_login_at" timestamptz NULL, "account_status" text NOT NULL DEFAULT 'active', PRIMARY KEY ("id"), CONSTRAINT "users_email_key" UNIQUE ("email"), CONSTRAINT "users_username_key" UNIQUE ("username"), CONSTRAINT "users_account_status_check" CHECK (account_status = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text])));
-- Create index "idx_users_account_status" to table: "users"
CREATE INDEX "idx_users_account_status" ON "users" ("account_status");
-- Create index "idx_users_email" to table: "users"
CREATE INDEX "idx_users_email" ON "users" ("email");
-- Create index "idx_users_username" to table: "users"
CREATE INDEX "idx_users_username" ON "users" ("username");
-- Create "webauthn_credentials" table
CREATE TABLE "webauthn_credentials" ("id" bytea NOT NULL, "user_id" uuid NOT NULL, "public_key" bytea NOT NULL, "aaguid" bytea NOT NULL, "sign_count" bigint NOT NULL DEFAULT 0, "clone_warning" boolean NOT NULL DEFAULT false, "attestation_type" text NULL, "transports" jsonb NULL DEFAULT '[]', "backup_eligible" boolean NOT NULL DEFAULT false, "backup_state" boolean NOT NULL DEFAULT false, "authenticator_attachment" text NULL, "credential_name" text NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "last_used_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "webauthn_credentials_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "idx_webauthn_credentials_last_used" to table: "webauthn_credentials"
CREATE INDEX "idx_webauthn_credentials_last_used" ON "webauthn_credentials" ("last_used_at");
-- Create index "idx_webauthn_credentials_user_id" to table: "webauthn_credentials"
CREATE INDEX "idx_webauthn_credentials_user_id" ON "webauthn_credentials" ("user_id");
-- Create "webauthn_sessions" table
CREATE TABLE "webauthn_sessions" ("session_id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NULL, "challenge" bytea NOT NULL, "operation" text NOT NULL, "user_verification" text NOT NULL, "created_at" timestamptz NOT NULL DEFAULT now(), "expires_at" timestamptz NOT NULL, PRIMARY KEY ("session_id"), CONSTRAINT "webauthn_sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "webauthn_sessions_operation_check" CHECK (operation = ANY (ARRAY['registration'::text, 'authentication'::text])), CONSTRAINT "webauthn_sessions_user_verification_check" CHECK (user_verification = ANY (ARRAY['required'::text, 'preferred'::text, 'discouraged'::text])));
-- Create index "idx_webauthn_sessions_expires_at" to table: "webauthn_sessions"
CREATE INDEX "idx_webauthn_sessions_expires_at" ON "webauthn_sessions" ("expires_at");
-- Create index "idx_webauthn_sessions_user_id" to table: "webauthn_sessions"
CREATE INDEX "idx_webauthn_sessions_user_id" ON "webauthn_sessions" ("user_id");
