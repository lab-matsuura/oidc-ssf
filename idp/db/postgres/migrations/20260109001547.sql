-- Modify "users" table
ALTER TABLE "users" ADD CONSTRAINT "users_role_check" CHECK (role = ANY (ARRAY['user'::text, 'admin'::text])), ADD COLUMN "role" text NOT NULL DEFAULT 'user';
-- Create index "idx_users_role" to table: "users"
CREATE INDEX "idx_users_role" ON "users" ("role");
