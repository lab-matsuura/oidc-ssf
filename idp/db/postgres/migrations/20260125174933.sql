-- Modify "idp_sessions" table
ALTER TABLE "idp_sessions" ADD COLUMN "user_agent" text NULL, ADD COLUMN "ip_address" text NULL;
