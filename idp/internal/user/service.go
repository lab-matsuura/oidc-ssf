package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrWeakPassword       = errors.New("password too weak")
	ErrOwnerAlreadyExists = errors.New("owner user already exists")
)

// Service handles user management operations
type Service struct {
	queries *sqlc.Queries
}

// NewService creates a new user service
func NewService(queries *sqlc.Queries) *Service {
	return &Service{
		queries: queries,
	}
}

// CreateUser registers a new user
func (s *Service) CreateUser(ctx context.Context, username, email, password, displayName string) (*sqlc.User, error) {
	// Validate inputs
	if username == "" || email == "" {
		return nil, errors.New("username and email are required")
	}

	// Hash password if provided (optional for passkey-only users)
	var passwordHash []byte
	if password != "" {
		// Validate password strength
		if len(password) < 8 {
			return nil, ErrWeakPassword
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		passwordHash = hash
	}

	// Create user
	var displayNamePtr *string
	if displayName != "" {
		displayNamePtr = &displayName
	}

	user, err := s.queries.CreateUser(ctx, sqlc.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		DisplayName:  displayNamePtr,
	})
	if err != nil {
		// Check for unique constraint violation
		if err.Error() == "duplicate key value violates unique constraint" {
			return nil, ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

// AuthenticateWithPassword verifies username/password credentials
func (s *Service) AuthenticateWithPassword(ctx context.Context, usernameOrEmail, password string) (*sqlc.User, error) {
	if usernameOrEmail == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	// Try to find user by username first
	user, err := s.queries.GetUserByUsername(ctx, usernameOrEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Try by email
			user, err = s.queries.GetUserByEmail(ctx, usernameOrEmail)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil, ErrUserNotFound
				}
				return nil, fmt.Errorf("failed to get user: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	}

	// Check if user has a password set
	if len(user.PasswordHash) == 0 {
		return nil, errors.New("user has no password set (passkey-only account)")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Update last login
	if err := s.queries.UpdateUserLastLogin(ctx, user.ID); err != nil {
		// Log error but don't fail auth
		fmt.Printf("warning: failed to update last login: %v\n", err)
	}

	return &user, nil
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(ctx context.Context, userID uuid.UUID) (*sqlc.User, error) {
	pgID := pgtype.UUID{}
	if err := pgID.Scan(userID); err != nil {
		return nil, fmt.Errorf("failed to convert UUID: %w", err)
	}
	user, err := s.queries.GetUserByID(ctx, pgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*sqlc.User, error) {
	user, err := s.queries.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*sqlc.User, error) {
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

// UpdatePassword updates a user's password
func (s *Service) UpdatePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	pgID := pgtype.UUID{}
	if err := pgID.Scan(userID); err != nil {
		return fmt.Errorf("failed to convert UUID: %w", err)
	}

	if err := s.queries.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           pgID,
		PasswordHash: hash,
	}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdateDisplayName updates a user's display name
func (s *Service) UpdateDisplayName(ctx context.Context, userID uuid.UUID, displayName string) error {
	pgID := pgtype.UUID{}
	if err := pgID.Scan(userID); err != nil {
		return fmt.Errorf("failed to convert UUID: %w", err)
	}

	var displayNamePtr *string
	if displayName != "" {
		displayNamePtr = &displayName
	}

	return s.queries.UpdateUserDisplayName(ctx, sqlc.UpdateUserDisplayNameParams{
		ID:          pgID,
		DisplayName: displayNamePtr,
	})
}

// HasOwner checks if an owner user exists in the system
func (s *Service) HasOwner(ctx context.Context) (bool, error) {
	result, err := s.queries.HasOwner(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check owner existence: %w", err)
	}
	return result, nil
}

// CreateOwner creates the owner user (only one owner can exist)
func (s *Service) CreateOwner(ctx context.Context, username, email, password, displayName string) (*sqlc.User, error) {
	// Validate inputs
	if username == "" || email == "" {
		return nil, errors.New("username and email are required")
	}

	// Check if owner already exists
	hasOwner, err := s.HasOwner(ctx)
	if err != nil {
		return nil, err
	}
	if hasOwner {
		return nil, ErrOwnerAlreadyExists
	}

	// Validate and hash password
	if password == "" {
		return nil, errors.New("password is required for owner")
	}
	if len(password) < 8 {
		return nil, ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create owner user
	var displayNamePtr *string
	if displayName != "" {
		displayNamePtr = &displayName
	}

	user, err := s.queries.CreateOwnerUser(ctx, sqlc.CreateOwnerUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		DisplayName:  displayNamePtr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create owner: %w", err)
	}

	return &user, nil
}

// IsOwner checks if the specified user is the owner
func (s *Service) IsOwner(ctx context.Context, userID uuid.UUID) (bool, error) {
	pgID := pgtype.UUID{}
	if err := pgID.Scan(userID); err != nil {
		return false, fmt.Errorf("failed to convert UUID: %w", err)
	}

	result, err := s.queries.IsUserOwner(ctx, pgID)
	if err != nil {
		return false, fmt.Errorf("failed to check owner status: %w", err)
	}
	return result, nil
}
