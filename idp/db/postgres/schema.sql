-- OAuth/OIDC Provider Database Schema
-- Managed by Atlas (https://atlasgo.io/)

-- OAuth Clients
-- Stores registered OAuth2/OIDC client applications
CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    secret BYTEA NOT NULL,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    grant_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authorization Codes
-- Stores authorization codes issued during OAuth2 authorization code flow
CREATE TABLE authorize_codes (
    code TEXT PRIMARY KEY,
    active BOOLEAN NOT NULL DEFAULT true,
    request_data BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authorize_codes_expires_at ON authorize_codes(expires_at);

-- Access Tokens
-- Stores issued access tokens with their associated request data
CREATE TABLE access_tokens (
    signature TEXT PRIMARY KEY,
    request_data BYTEA NOT NULL,
    request_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_tokens_request_id ON access_tokens(request_id);
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);

-- Refresh Tokens
-- Stores refresh tokens with reference to associated access tokens
CREATE TABLE refresh_tokens (
    signature TEXT PRIMARY KEY,
    active BOOLEAN NOT NULL DEFAULT true,
    request_data BYTEA NOT NULL,
    request_id TEXT NOT NULL,
    access_token_signature TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_request_id ON refresh_tokens(request_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- OpenID Connect Sessions
-- Stores OIDC session data associated with authorization codes
CREATE TABLE oidc_sessions (
    authorize_code TEXT PRIMARY KEY,
    request_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- PKCE Sessions
-- Stores PKCE (Proof Key for Code Exchange) challenge data
CREATE TABLE pkce_sessions (
    code TEXT PRIMARY KEY,
    request_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Blacklisted JTIs (JWT Token IDs)
-- Prevents JWT replay attacks by tracking used JTIs
CREATE TABLE blacklisted_jtis (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_blacklisted_jtis_expires_at ON blacklisted_jtis(expires_at);

-- PAR (Pushed Authorization Request) Sessions
-- Stores pushed authorization request data (RFC 9126)
CREATE TABLE par_sessions (
    request_uri TEXT PRIMARY KEY,
    request_data BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_par_sessions_expires_at ON par_sessions(expires_at);

-- Users
-- Stores user accounts with authentication credentials
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    password_hash BYTEA,  -- NULL allowed for passwordless users
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'owner')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    account_status TEXT NOT NULL DEFAULT 'active' CHECK (account_status IN ('active', 'suspended', 'deleted'))
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_account_status ON users(account_status);
CREATE INDEX idx_users_role ON users(role);

-- SSF (Shared Signals Framework) Streams
-- Stores SSF stream configurations for event delivery
CREATE TABLE ssf_streams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT,  -- Owner client ID for authorization
    audience TEXT[] NOT NULL,
    delivery_method TEXT NOT NULL DEFAULT 'urn:ietf:rfc:8935',
    endpoint_url TEXT NOT NULL,
    authorization_header TEXT,  -- Authorization header for Push delivery to receiver
    events_requested TEXT[] NOT NULL DEFAULT '{}',
    events_delivered TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'paused', 'disabled')),
    status_reason TEXT,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssf_streams_status ON ssf_streams(status);
CREATE INDEX idx_ssf_streams_created_at ON ssf_streams(created_at);

-- SSF Stream Subjects
-- Stores subjects (users) that are included/excluded from a stream
CREATE TABLE ssf_stream_subjects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    subject_format TEXT NOT NULL,
    subject_identifier TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(stream_id, subject_format, subject_identifier)
);

CREATE INDEX idx_ssf_stream_subjects_stream_id ON ssf_stream_subjects(stream_id);
CREATE INDEX idx_ssf_stream_subjects_identifier ON ssf_stream_subjects(subject_identifier);

-- SSF Events (normalized)
-- Stores event data once, regardless of how many streams receive it
CREATE TABLE ssf_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    subject_identifier TEXT,
    payload JSONB NOT NULL,  -- Full SET payload (stored once)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssf_events_type ON ssf_events(event_type);
CREATE INDEX idx_ssf_events_subject ON ssf_events(subject_identifier);
CREATE INDEX idx_ssf_events_created_at ON ssf_events(created_at);

-- SSF Event Deliveries (normalized)
-- Tracks delivery status per stream (Push and Poll unified)
CREATE TABLE ssf_event_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES ssf_events(id) ON DELETE CASCADE,
    stream_id UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
    jti TEXT NOT NULL UNIQUE,
    set_token TEXT NOT NULL,  -- Signed JWT token for delivery
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'failed', 'retry', 'acked')),
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 10,
    last_error TEXT,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    acked_at TIMESTAMPTZ,
    UNIQUE(event_id, stream_id)
);

CREATE INDEX idx_ssf_deliveries_event ON ssf_event_deliveries(event_id);
CREATE INDEX idx_ssf_deliveries_stream ON ssf_event_deliveries(stream_id);
CREATE INDEX idx_ssf_deliveries_jti ON ssf_event_deliveries(jti);
CREATE INDEX idx_ssf_deliveries_status ON ssf_event_deliveries(status);
CREATE INDEX idx_ssf_deliveries_pending ON ssf_event_deliveries(status, next_retry_at)
    WHERE status IN ('queued', 'retry');

-- IdP Sessions
-- Stores server-side sessions for proper SLO (Single Logout) support
CREATE TABLE idp_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent TEXT,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ  -- Set on SLO, NULL = active
);

CREATE INDEX idx_idp_sessions_user_id ON idp_sessions(user_id);
