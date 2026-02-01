package portal

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
)

type contextKey string

const (
	CurrentUserKey contextKey = "current_user"
	SessionCookie  string     = "idp_session"
)

// Middleware provides portal authentication middleware
type Middleware struct {
	queries *sqlc.Queries
}

// NewMiddleware creates a new portal middleware
func NewMiddleware(queries *sqlc.Queries) *Middleware {
	return &Middleware{queries: queries}
}

// RequireAuth is a middleware that requires any authenticated user
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := m.getUserFromSession(r)
		if user == nil {
			// Redirect to login with return URL
			http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusSeeOther)
			return
		}

		// Check if user is active
		if user.AccountStatus != "active" {
			http.Error(w, "Account is disabled", http.StatusForbidden)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), CurrentUserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin is a middleware that requires admin or owner role
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetCurrentUser(r.Context())
		if user == nil {
			http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusSeeOther)
			return
		}

		// Check if user is admin or owner
		if user.Role != "admin" && user.Role != "owner" {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getUserFromSession retrieves user from session cookie (server-side session)
func (m *Middleware) getUserFromSession(r *http.Request) *sqlc.User {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil
	}

	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return nil
	}

	pgSessionID := pgtype.UUID{
		Bytes: sessionID,
		Valid: true,
	}

	// Look up session from DB (checks revoked_at and expires_at)
	session, err := m.queries.GetIDPSession(r.Context(), pgSessionID)
	if err != nil {
		return nil
	}

	// Get user from session
	user, err := m.queries.GetUserByIDIncludeInactive(r.Context(), session.UserID)
	if err != nil {
		return nil
	}

	return &user
}

// GetCurrentUser retrieves the current user from context
func GetCurrentUser(ctx context.Context) *sqlc.User {
	user, ok := ctx.Value(CurrentUserKey).(*sqlc.User)
	if !ok {
		return nil
	}
	return user
}

// IsAdmin checks if the current user is admin or owner
func IsAdmin(ctx context.Context) bool {
	user := GetCurrentUser(ctx)
	if user == nil {
		return false
	}
	return user.Role == "admin" || user.Role == "owner"
}

// CreateSession creates a server-side session and sets the cookie
func (m *Middleware) CreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, userID uuid.UUID) error {
	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}
	expiresAt := pgtype.Timestamptz{
		Time:  time.Now().Add(24 * time.Hour),
		Valid: true,
	}

	// Extract User-Agent and IP address from request
	userAgent := r.UserAgent()
	ipAddress := getClientIP(r)

	session, err := m.queries.CreateIDPSession(ctx, sqlc.CreateIDPSessionParams{
		UserID:    pgUserID,
		UserAgent: &userAgent,
		IpAddress: &ipAddress,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return err
	}

	// Set cookie with session ID
	sessionID := uuid.UUID(session.ID.Bytes)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    sessionID.String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})

	return nil
}

// RevokeUserSessions revokes all sessions for a user (SLO)
func (m *Middleware) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}
	return m.queries.RevokeUserSessions(ctx, pgUserID)
}

// SetSessionCookie sets the IdP session cookie (deprecated - use CreateSession)
func SetSessionCookie(w http.ResponseWriter, userID uuid.UUID) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    userID.String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})
}

// ClearSessionCookie clears the IdP session cookie
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (handles both IPv4 and IPv6)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port
		return r.RemoteAddr
	}
	return host
}
