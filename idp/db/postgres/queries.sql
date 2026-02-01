-- OAuth Clients
-- name: GetClient :one
SELECT * FROM clients WHERE id = $1 LIMIT 1;

-- name: CreateClient :exec
INSERT INTO clients (
    id, secret, redirect_uris, grant_types, response_types, scopes, public
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
);

-- name: UpdateClient :exec
UPDATE clients SET
    secret = $2,
    redirect_uris = $3,
    grant_types = $4,
    response_types = $5,
    scopes = $6,
    public = $7,
    updated_at = NOW()
WHERE id = $1;

-- Authorization Codes
-- name: CreateAuthorizeCode :exec
INSERT INTO authorize_codes (code, active, request_data, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetAuthorizeCode :one
SELECT * FROM authorize_codes WHERE code = $1 LIMIT 1;

-- name: InvalidateAuthorizeCode :exec
UPDATE authorize_codes SET active = false WHERE code = $1;

-- name: DeleteExpiredAuthorizeCodes :exec
DELETE FROM authorize_codes WHERE expires_at < NOW();

-- Access Tokens
-- name: CreateAccessToken :exec
INSERT INTO access_tokens (signature, request_data, request_id, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetAccessToken :one
SELECT * FROM access_tokens WHERE signature = $1 LIMIT 1;

-- name: GetAccessTokenByRequestID :one
SELECT * FROM access_tokens WHERE request_id = $1 LIMIT 1;

-- name: DeleteAccessToken :exec
DELETE FROM access_tokens WHERE signature = $1;

-- name: DeleteAccessTokenByRequestID :exec
DELETE FROM access_tokens WHERE request_id = $1;

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens WHERE expires_at < NOW();

-- Refresh Tokens
-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (
    signature, active, request_data, request_id, access_token_signature, expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6
);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE signature = $1 LIMIT 1;

-- name: GetRefreshTokenByRequestID :one
SELECT * FROM refresh_tokens WHERE request_id = $1 LIMIT 1;

-- name: InvalidateRefreshToken :exec
UPDATE refresh_tokens SET active = false WHERE signature = $1;

-- name: InvalidateRefreshTokenByRequestID :exec
UPDATE refresh_tokens SET active = false WHERE request_id = $1;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens WHERE signature = $1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < NOW();

-- OIDC Sessions
-- name: CreateOIDCSession :exec
INSERT INTO oidc_sessions (authorize_code, request_data)
VALUES ($1, $2);

-- name: GetOIDCSession :one
SELECT * FROM oidc_sessions WHERE authorize_code = $1 LIMIT 1;

-- name: DeleteOIDCSession :exec
DELETE FROM oidc_sessions WHERE authorize_code = $1;

-- PKCE Sessions
-- name: CreatePKCESession :exec
INSERT INTO pkce_sessions (code, request_data)
VALUES ($1, $2);

-- name: GetPKCESession :one
SELECT * FROM pkce_sessions WHERE code = $1 LIMIT 1;

-- name: DeletePKCESession :exec
DELETE FROM pkce_sessions WHERE code = $1;

-- Blacklisted JTIs
-- name: IsJTIBlacklisted :one
SELECT EXISTS(
    SELECT 1 FROM blacklisted_jtis
    WHERE jti = $1 AND expires_at > NOW()
) AS exists;

-- name: BlacklistJTI :exec
INSERT INTO blacklisted_jtis (jti, expires_at)
VALUES ($1, $2)
ON CONFLICT (jti) DO NOTHING;

-- name: CleanupExpiredJTIs :exec
DELETE FROM blacklisted_jtis WHERE expires_at < NOW();

-- PAR Sessions
-- name: CreatePARSession :exec
INSERT INTO par_sessions (request_uri, request_data, expires_at)
VALUES ($1, $2, $3);

-- name: GetPARSession :one
SELECT * FROM par_sessions WHERE request_uri = $1 LIMIT 1;

-- name: DeletePARSession :exec
DELETE FROM par_sessions WHERE request_uri = $1;

-- name: DeleteExpiredPARSessions :exec
DELETE FROM par_sessions WHERE expires_at < NOW();

-- Users
-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, display_name)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 AND account_status = 'active' LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1 AND account_status = 'active' LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 AND account_status = 'active' LIMIT 1;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login_at = NOW() WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1;

-- name: UpdateUserEmailVerified :exec
UPDATE users SET email_verified = $2, updated_at = NOW() WHERE id = $1;

-- name: UpdateUserDisplayName :exec
UPDATE users SET display_name = $2, updated_at = NOW() WHERE id = $1;

-- name: UpdateUserAccountStatus :exec
UPDATE users SET account_status = $2, updated_at = NOW() WHERE id = $1;

-- ===================
-- Admin: Client Management
-- ===================

-- name: ListClients :many
SELECT * FROM clients ORDER BY created_at DESC;

-- name: DeleteClient :exec
DELETE FROM clients WHERE id = $1;

-- name: CountClients :one
SELECT COUNT(*) FROM clients;

-- name: UpdateClientSecret :exec
UPDATE clients SET secret = $2, updated_at = NOW() WHERE id = $1;

-- ===================
-- Admin: User Management
-- ===================

-- name: ListUsers :many
SELECT * FROM users
WHERE account_status != 'deleted'
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE account_status != 'deleted';

-- name: ListUsersByStatus :many
SELECT * FROM users
WHERE account_status = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: SearchUsers :many
SELECT * FROM users
WHERE (username ILIKE $1 OR email ILIKE $1 OR display_name ILIKE $1)
  AND account_status != 'deleted'
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: GetAdminUsers :many
SELECT * FROM users WHERE role = 'admin' AND account_status = 'active';

-- name: UpdateUserRole :exec
UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1;

-- name: IsUserAdmin :one
SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND role = 'admin' AND account_status = 'active') AS is_admin;

-- name: IsUserOwner :one
SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND role = 'owner' AND account_status = 'active') AS is_owner;

-- name: IsUserAdminOrOwner :one
SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND role IN ('admin', 'owner') AND account_status = 'active') AS is_admin_or_owner;

-- name: GetOwnerUser :one
SELECT * FROM users WHERE role = 'owner' AND account_status = 'active' LIMIT 1;

-- ===================
-- IdP Sessions (for SLO)
-- ===================

-- name: CreateIDPSession :one
INSERT INTO idp_sessions (user_id, user_agent, ip_address, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetIDPSession :one
SELECT * FROM idp_sessions
WHERE id = $1 AND revoked_at IS NULL AND expires_at > NOW()
LIMIT 1;

-- name: RevokeUserSessions :exec
-- Revoke all active sessions for a user (used by SLO)
UPDATE idp_sessions
SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeSession :exec
UPDATE idp_sessions
SET revoked_at = NOW()
WHERE id = $1;

-- name: ListUserSessions :many
SELECT * FROM idp_sessions
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUserSessions :one
SELECT COUNT(*) FROM idp_sessions
WHERE user_id = $1;

-- name: CleanupExpiredSessions :exec
DELETE FROM idp_sessions
WHERE expires_at < NOW() - INTERVAL '30 days';

-- name: HasOwner :one
SELECT EXISTS(SELECT 1 FROM users WHERE role = 'owner' AND account_status != 'deleted') AS has_owner;

-- name: CreateOwnerUser :one
INSERT INTO users (username, email, password_hash, display_name, role)
VALUES ($1, $2, $3, $4, 'owner')
RETURNING *;

-- name: GetUserByIDIncludeInactive :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- ===================
-- Admin: Statistics
-- ===================

-- name: GetActiveSessionCount :one
SELECT COUNT(*) FROM access_tokens WHERE created_at > NOW() - INTERVAL '1 hour';

-- name: GetRecentLoginCount :one
SELECT COUNT(*) FROM users WHERE last_login_at > NOW() - INTERVAL '24 hours';

-- name: CreateUserByAdmin :one
-- Admin creates a user with optional role
INSERT INTO users (username, email, password_hash, display_name, role)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: CheckUsernameExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) AS exists;

-- name: CheckEmailExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) AS exists;

-- ===================
-- SSF: Streams
-- ===================

-- name: CreateSSFStream :one
INSERT INTO ssf_streams (
    client_id, audience, delivery_method, endpoint_url, authorization_header,
    events_requested, events_delivered, description
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetSSFStream :one
SELECT * FROM ssf_streams WHERE id = $1 LIMIT 1;

-- name: GetSSFStreamByClientID :many
SELECT * FROM ssf_streams WHERE client_id = $1 ORDER BY created_at DESC;

-- name: ListSSFStreams :many
SELECT * FROM ssf_streams ORDER BY created_at DESC;

-- name: ListSSFStreamsByStatus :many
SELECT * FROM ssf_streams WHERE status = $1 ORDER BY created_at DESC;

-- name: UpdateSSFStream :exec
UPDATE ssf_streams SET
    audience = $2,
    delivery_method = $3,
    endpoint_url = $4,
    authorization_header = $5,
    events_requested = $6,
    events_delivered = $7,
    description = $8,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateSSFStreamStatus :exec
UPDATE ssf_streams SET
    status = $2,
    status_reason = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteSSFStream :exec
DELETE FROM ssf_streams WHERE id = $1;

-- name: CountSSFStreams :one
SELECT COUNT(*) FROM ssf_streams;

-- name: CountSSFStreamsByStatus :one
SELECT COUNT(*) FROM ssf_streams WHERE status = $1;

-- ===================
-- SSF: Stream Subjects
-- ===================

-- name: CreateSSFStreamSubject :one
INSERT INTO ssf_stream_subjects (stream_id, subject_format, subject_identifier, verified)
VALUES ($1, $2, $3, $4)
ON CONFLICT (stream_id, subject_format, subject_identifier) DO UPDATE
SET verified = EXCLUDED.verified
RETURNING *;

-- name: GetSSFStreamSubject :one
SELECT * FROM ssf_stream_subjects
WHERE stream_id = $1 AND subject_format = $2 AND subject_identifier = $3
LIMIT 1;

-- name: ListSSFStreamSubjects :many
SELECT * FROM ssf_stream_subjects
WHERE stream_id = $1
ORDER BY created_at DESC;

-- name: DeleteSSFStreamSubject :exec
DELETE FROM ssf_stream_subjects
WHERE stream_id = $1 AND subject_format = $2 AND subject_identifier = $3;

-- name: DeleteAllSSFStreamSubjects :exec
DELETE FROM ssf_stream_subjects WHERE stream_id = $1;

-- name: GetStreamsBySubjectIdentifier :many
-- Subject が登録されているストリーム（enabled のみ）を取得
SELECT DISTINCT s.* FROM ssf_streams s
JOIN ssf_stream_subjects sub ON s.id = sub.stream_id
WHERE sub.subject_identifier = $1 AND s.status = 'enabled';

-- name: IsSubjectInStream :one
-- 特定の Subject がストリームに登録されているか確認
SELECT EXISTS(
  SELECT 1 FROM ssf_stream_subjects
  WHERE stream_id = $1 AND subject_identifier = $2
) AS exists;

-- ===================
-- SSF: Events (normalized)
-- ===================

-- name: CreateSSFEvent :one
INSERT INTO ssf_events (event_type, subject_identifier, payload)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetSSFEvent :one
SELECT * FROM ssf_events WHERE id = $1 LIMIT 1;

-- name: ListSSFEvents :many
SELECT * FROM ssf_events
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountSSFEvents :one
SELECT COUNT(*) FROM ssf_events;

-- name: CleanupOldSSFEvents :exec
DELETE FROM ssf_events WHERE created_at < NOW() - INTERVAL '30 days';

-- ===================
-- SSF: Event Deliveries (normalized)
-- ===================

-- name: CreateSSFEventDelivery :one
INSERT INTO ssf_event_deliveries (event_id, stream_id, jti, set_token, status, next_retry_at)
VALUES ($1, $2, $3, $4, $5, NOW())
RETURNING *;

-- name: GetSSFEventDelivery :one
SELECT * FROM ssf_event_deliveries WHERE id = $1 LIMIT 1;

-- name: GetSSFEventDeliveryByIDWithDetails :one
-- Fetch a single delivery with all details needed for processing
SELECT d.*, e.payload, s.endpoint_url, s.authorization_header, s.delivery_method
FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
JOIN ssf_streams s ON d.stream_id = s.id
WHERE d.id = $1;

-- name: LockSSFEventDeliveryForProcessing :one
-- Lock a single delivery for immediate processing (used by goroutine)
-- Uses FOR UPDATE SKIP LOCKED to avoid conflicts with DB poller
-- Returns no rows if already locked or not in queued status
SELECT d.*, e.payload, s.endpoint_url, s.authorization_header, s.delivery_method
FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
JOIN ssf_streams s ON d.stream_id = s.id
WHERE d.id = $1
  AND d.status = 'queued'
  AND s.delivery_method = 'urn:ietf:rfc:8935'
FOR UPDATE OF d SKIP LOCKED;

-- name: GetSSFEventDeliveryByJTI :one
SELECT * FROM ssf_event_deliveries WHERE jti = $1 LIMIT 1;

-- name: ListSSFEventDeliveries :many
SELECT d.*, e.event_type, e.subject_identifier
FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
ORDER BY d.created_at DESC
LIMIT $1 OFFSET $2;

-- name: ListSSFEventDeliveriesByStream :many
SELECT d.*, e.event_type, e.subject_identifier
FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
WHERE d.stream_id = $1
ORDER BY d.created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListSSFEventDeliveriesByEvent :many
SELECT d.*, s.endpoint_url, s.delivery_method
FROM ssf_event_deliveries d
JOIN ssf_streams s ON d.stream_id = s.id
WHERE d.event_id = $1
ORDER BY d.created_at DESC;

-- name: GetPendingSSFDeliveries :many
-- Fetch deliveries ready for transmission (Push: queued/retry with next_retry_at <= now)
-- FOR UPDATE SKIP LOCKED ensures no duplicate processing in multi-instance environments
SELECT d.*, e.payload, s.endpoint_url, s.authorization_header, s.delivery_method
FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
JOIN ssf_streams s ON d.stream_id = s.id
WHERE d.status IN ('queued', 'retry')
  AND d.next_retry_at <= NOW()
  AND d.attempts < d.max_attempts
  AND s.status = 'enabled'
  AND s.delivery_method = 'urn:ietf:rfc:8935'
ORDER BY d.created_at ASC
LIMIT $1
FOR UPDATE OF d SKIP LOCKED;

-- name: GetPollSSFDeliveries :many
-- Fetch deliveries for Poll (queued or sent but not acked)
SELECT d.jti, d.set_token
FROM ssf_event_deliveries d
JOIN ssf_streams s ON d.stream_id = s.id
WHERE d.stream_id = $1
  AND d.status IN ('queued', 'sent')
  AND s.delivery_method = 'urn:ietf:rfc:8936'
ORDER BY d.created_at ASC
LIMIT $2;

-- name: MarkSSFDeliverySent :exec
UPDATE ssf_event_deliveries SET
    status = 'sent',
    sent_at = NOW(),
    last_error = NULL
WHERE id = $1;

-- name: MarkSSFDeliveryFailed :exec
UPDATE ssf_event_deliveries SET
    status = CASE WHEN attempts + 1 >= max_attempts THEN 'failed' ELSE 'retry' END,
    attempts = attempts + 1,
    last_error = $2,
    next_retry_at = NOW() + ($3 * INTERVAL '1 second')
WHERE id = $1;

-- name: AckSSFDeliveries :exec
UPDATE ssf_event_deliveries
SET status = 'acked', acked_at = NOW()
WHERE stream_id = $1 AND jti = ANY($2::text[]);

-- name: AckSSFDelivery :exec
UPDATE ssf_event_deliveries
SET status = 'acked', acked_at = NOW()
WHERE stream_id = $1 AND jti = $2;

-- name: CountSSFEventDeliveries :one
SELECT COUNT(*) FROM ssf_event_deliveries;

-- name: CountSSFEventDeliveriesByStream :one
SELECT COUNT(*) FROM ssf_event_deliveries WHERE stream_id = $1;

-- name: CountSSFEventDeliveriesByStatus :one
SELECT COUNT(*) FROM ssf_event_deliveries WHERE status = $1;

-- name: ListSSFEventDeliveriesFiltered :many
SELECT d.*, e.event_type, e.subject_identifier
FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
WHERE (sqlc.narg('stream_id')::uuid IS NULL OR d.stream_id = sqlc.narg('stream_id'))
  AND (sqlc.narg('status')::text IS NULL OR d.status = sqlc.narg('status'))
  AND (sqlc.narg('event_type')::text IS NULL OR e.event_type = sqlc.narg('event_type'))
ORDER BY d.created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountSSFEventDeliveriesFiltered :one
SELECT COUNT(*) FROM ssf_event_deliveries d
JOIN ssf_events e ON d.event_id = e.id
WHERE (sqlc.narg('stream_id')::uuid IS NULL OR d.stream_id = sqlc.narg('stream_id'))
  AND (sqlc.narg('status')::text IS NULL OR d.status = sqlc.narg('status'))
  AND (sqlc.narg('event_type')::text IS NULL OR e.event_type = sqlc.narg('event_type'));

-- name: GetSSFDeliveryStats :one
SELECT
  COUNT(*) as total_deliveries,
  COUNT(*) FILTER (WHERE status = 'sent') as sent_count,
  COUNT(*) FILTER (WHERE status = 'acked') as acked_count,
  COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
  COUNT(*) FILTER (WHERE status = 'queued' OR status = 'retry') as pending_count
FROM ssf_event_deliveries;

-- name: GetRecentSSFDeliveryCount :one
SELECT COUNT(*) FROM ssf_event_deliveries WHERE created_at > NOW() - INTERVAL '24 hours';

-- name: CleanupOldSSFDeliveries :exec
DELETE FROM ssf_event_deliveries WHERE created_at < NOW() - INTERVAL '30 days';
