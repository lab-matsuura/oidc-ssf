-- RP (Relying Party) Database Schema
-- Managed by Atlas (https://atlasgo.io/)

-- RP Users
-- Stores user information received from IdP
CREATE TABLE users (
    sub TEXT PRIMARY KEY,               -- IdP subject identifier (unique per user)
    email TEXT,                         -- User email from IdP
    name TEXT,                          -- User display name from IdP
    role TEXT NOT NULL DEFAULT 'user',  -- User role in RP: 'admin' or 'user'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- RP Sessions
-- Server-side session management
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,                -- Random session ID
    user_sub TEXT NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
    access_token TEXT NOT NULL,         -- OAuth access token
    id_token TEXT NOT NULL,             -- OIDC ID token
    refresh_token TEXT,                 -- OAuth refresh token (optional)
    expires_at TIMESTAMPTZ NOT NULL,    -- Session expiration time
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_sub ON sessions(user_sub);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- SSF Stream Configuration
-- Stores the RP's SSF stream information (token is managed in memory)
CREATE TABLE ssf_config (
    id INTEGER PRIMARY KEY DEFAULT 1,
    stream_id TEXT,                     -- SSF stream ID (persistent)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT single_row CHECK (id = 1)
);
