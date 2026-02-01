-- Modify "users" table
ALTER TABLE "users" DROP CONSTRAINT "users_role_check", ADD CONSTRAINT "users_role_check" CHECK (role = ANY (ARRAY['user'::text, 'admin'::text, 'owner'::text]));
