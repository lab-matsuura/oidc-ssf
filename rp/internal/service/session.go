package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/storage/postgres/sqlc"
)

// UserSession represents a user session (compatible with existing code)
type UserSession struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	AccessToken  string    `json:"access_token"`
	IDToken      string    `json:"id_token"`
	RefreshToken string    `json:"refresh_token"`
	UserInfo     UserInfo  `json:"user_info"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// UserInfo represents user information from the IdP
type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// SessionService manages user sessions using PostgreSQL
type SessionService struct {
	queries       *sqlc.Queries
	states        map[string]time.Time // For CSRF protection (in-memory for simplicity)
	mutex         sync.RWMutex
	secureCookies bool
}

// NewSessionService creates a new session service
func NewSessionService(queries *sqlc.Queries, secureCookies bool) *SessionService {
	return &SessionService{
		queries:       queries,
		states:        make(map[string]time.Time),
		secureCookies: secureCookies,
	}
}

// CreateState generates a random state parameter for CSRF protection
func (s *SessionService) CreateState() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	state := hex.EncodeToString(bytes)

	s.mutex.Lock()
	s.states[state] = time.Now().Add(10 * time.Minute)
	s.mutex.Unlock()

	return state
}

// ValidateState validates the state parameter
func (s *SessionService) ValidateState(state string) bool {
	s.mutex.RLock()
	expiry, exists := s.states[state]
	s.mutex.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		s.mutex.Lock()
		delete(s.states, state)
		s.mutex.Unlock()
		return false
	}

	// Remove used state
	s.mutex.Lock()
	delete(s.states, state)
	s.mutex.Unlock()

	return true
}

// CreateSession creates a new user session in the database
func (s *SessionService) CreateSession(ctx context.Context, userSub, accessToken, idToken, refreshToken string, expiresAt time.Time) (*UserSession, error) {
	sessionID := s.generateSessionID()

	var refreshTokenPtr *string
	if refreshToken != "" {
		refreshTokenPtr = &refreshToken
	}

	session, err := s.queries.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:           sessionID,
		UserSub:      userSub,
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshTokenPtr,
		ExpiresAt:    pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return nil, err
	}

	return s.sessionToUserSession(&session), nil
}

// GetSession retrieves a session by ID
func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*UserSession, bool) {
	session, err := s.queries.GetSessionWithUser(ctx, sessionID)
	if err != nil {
		return nil, false
	}

	return s.sessionWithUserToUserSession(&session), true
}

// DeleteSession removes a session
func (s *SessionService) DeleteSession(ctx context.Context, sessionID string) error {
	return s.queries.DeleteSession(ctx, sessionID)
}

// GetSessionFromRequest extracts session from HTTP request
func (s *SessionService) GetSessionFromRequest(r *http.Request) (*UserSession, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, false
	}

	return s.GetSession(r.Context(), cookie.Value)
}

// SetSessionCookie sets the session cookie in HTTP response
func (s *SessionService) SetSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie removes the session cookie
func (s *SessionService) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
}

// RevokeSessionsByUserSub revokes all sessions for a specific user
func (s *SessionService) RevokeSessionsByUserSub(ctx context.Context, userSub string) (int64, error) {
	return s.queries.DeleteSessionsByUserSub(ctx, userSub)
}

// DeleteExpiredSessions removes all expired sessions
func (s *SessionService) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	return s.queries.DeleteExpiredSessions(ctx)
}

// GetAllSessions returns all active sessions (for debugging/admin)
func (s *SessionService) GetAllSessions(ctx context.Context) map[string]*UserSession {
	sessions, err := s.queries.ListAllSessions(ctx)
	if err != nil {
		return make(map[string]*UserSession)
	}

	result := make(map[string]*UserSession, len(sessions))
	for _, session := range sessions {
		result[session.ID] = s.listAllSessionsRowToUserSession(&session)
	}
	return result
}

// Helper functions

func (s *SessionService) generateSessionID() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *SessionService) sessionToUserSession(session *sqlc.Session) *UserSession {
	refreshToken := ""
	if session.RefreshToken != nil {
		refreshToken = *session.RefreshToken
	}

	return &UserSession{
		ID:           session.ID,
		Username:     session.UserSub,
		AccessToken:  session.AccessToken,
		IDToken:      session.IDToken,
		RefreshToken: refreshToken,
		CreatedAt:    session.CreatedAt.Time,
		ExpiresAt:    session.ExpiresAt.Time,
	}
}

func (s *SessionService) sessionWithUserToUserSession(session *sqlc.GetSessionWithUserRow) *UserSession {
	refreshToken := ""
	if session.RefreshToken != nil {
		refreshToken = *session.RefreshToken
	}

	name := ""
	if session.UserName != nil {
		name = *session.UserName
	}

	email := ""
	if session.UserEmail != nil {
		email = *session.UserEmail
	}

	role := session.UserRole
	if role == "" {
		role = "user"
	}

	return &UserSession{
		ID:           session.ID,
		Username:     session.UserSub,
		AccessToken:  session.AccessToken,
		IDToken:      session.IDToken,
		RefreshToken: refreshToken,
		UserInfo: UserInfo{
			Sub:   session.UserSub,
			Name:  name,
			Email: email,
			Role:  role,
		},
		Role:      role,
		CreatedAt: session.CreatedAt.Time,
		ExpiresAt: session.ExpiresAt.Time,
	}
}

func (s *SessionService) listAllSessionsRowToUserSession(session *sqlc.ListAllSessionsRow) *UserSession {
	refreshToken := ""
	if session.RefreshToken != nil {
		refreshToken = *session.RefreshToken
	}

	name := ""
	if session.UserName != nil {
		name = *session.UserName
	}

	email := ""
	if session.UserEmail != nil {
		email = *session.UserEmail
	}

	role := session.UserRole
	if role == "" {
		role = "user"
	}

	return &UserSession{
		ID:           session.ID,
		Username:     session.UserSub,
		AccessToken:  session.AccessToken,
		IDToken:      session.IDToken,
		RefreshToken: refreshToken,
		UserInfo: UserInfo{
			Sub:   session.UserSub,
			Name:  name,
			Email: email,
			Role:  role,
		},
		Role:      role,
		CreatedAt: session.CreatedAt.Time,
		ExpiresAt: session.ExpiresAt.Time,
	}
}
