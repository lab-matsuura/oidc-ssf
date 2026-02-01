-- ===================
-- Users
-- ===================

-- name: GetUser :one
SELECT * FROM users WHERE sub = $1 LIMIT 1;

-- name: CreateOrUpdateUser :one
INSERT INTO users (sub, email, name, role)
VALUES ($1, $2, $3, $4)
ON CONFLICT (sub) DO UPDATE SET
    email = EXCLUDED.email,
    name = EXCLUDED.name,
    updated_at = NOW()
RETURNING *;

-- name: UpdateUserRole :exec
UPDATE users SET role = $2, updated_at = NOW() WHERE sub = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: DeleteUser :exec
DELETE FROM users WHERE sub = $1;

-- ===================
-- Sessions
-- ===================

-- name: CreateSession :one
INSERT INTO sessions (id, user_sub, access_token, id_token, refresh_token, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions
WHERE id = $1 AND expires_at > NOW()
LIMIT 1;

-- name: GetSessionWithUser :one
SELECT
    s.id,
    s.user_sub,
    s.access_token,
    s.id_token,
    s.refresh_token,
    s.expires_at,
    s.created_at,
    u.email as user_email,
    u.name as user_name,
    u.role as user_role
FROM sessions s
JOIN users u ON s.user_sub = u.sub
WHERE s.id = $1 AND s.expires_at > NOW()
LIMIT 1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteSessionsByUserSub :execrows
DELETE FROM sessions WHERE user_sub = $1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at < NOW();

-- name: ListSessionsByUser :many
SELECT * FROM sessions WHERE user_sub = $1 ORDER BY created_at DESC;

-- name: CountSessionsByUser :one
SELECT COUNT(*) FROM sessions WHERE user_sub = $1;

-- name: ListAllSessions :many
SELECT
    s.id,
    s.user_sub,
    s.access_token,
    s.id_token,
    s.refresh_token,
    s.expires_at,
    s.created_at,
    u.email as user_email,
    u.name as user_name,
    u.role as user_role
FROM sessions s
JOIN users u ON s.user_sub = u.sub
WHERE s.expires_at > NOW()
ORDER BY s.created_at DESC;

-- ===================
-- SSF Config
-- ===================

-- name: GetSSFConfig :one
SELECT * FROM ssf_config WHERE id = 1 LIMIT 1;

-- name: UpsertSSFConfig :one
INSERT INTO ssf_config (id, stream_id)
VALUES (1, $1)
ON CONFLICT (id) DO UPDATE SET
    stream_id = EXCLUDED.stream_id,
    updated_at = NOW()
RETURNING *;

-- name: DeleteSSFConfig :exec
DELETE FROM ssf_config WHERE id = 1;
