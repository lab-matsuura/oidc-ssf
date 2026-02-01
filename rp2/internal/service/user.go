package service

import (
	"context"
	"time"

	"github.com/lab-matsuura/oidc-ssf/rp2/internal/storage/postgres/sqlc"
)

// User represents a user in the RP database
type User struct {
	Sub       string    `json:"sub"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserService manages users in the RP database
type UserService struct {
	queries *sqlc.Queries
}

// NewUserService creates a new user service
func NewUserService(queries *sqlc.Queries) *UserService {
	return &UserService{
		queries: queries,
	}
}

// CreateOrUpdateUser creates a new user or updates an existing one
// If role is empty, defaults to "user"
func (s *UserService) CreateOrUpdateUser(ctx context.Context, sub, email, name, role string) (*User, error) {
	// Use role from ID token claims, default to "user" if not provided
	if role == "" {
		role = "user"
	}

	var emailPtr, namePtr *string
	if email != "" {
		emailPtr = &email
	}
	if name != "" {
		namePtr = &name
	}

	user, err := s.queries.CreateOrUpdateUser(ctx, sqlc.CreateOrUpdateUserParams{
		Sub:   sub,
		Email: emailPtr,
		Name:  namePtr,
		Role:  role,
	})
	if err != nil {
		return nil, err
	}

	return s.sqlcUserToUser(&user), nil
}

// GetUser retrieves a user by their sub
func (s *UserService) GetUser(ctx context.Context, sub string) (*User, error) {
	user, err := s.queries.GetUser(ctx, sub)
	if err != nil {
		return nil, err
	}

	return s.sqlcUserToUser(&user), nil
}

// UpdateUserRole updates a user's role
func (s *UserService) UpdateUserRole(ctx context.Context, sub, role string) error {
	return s.queries.UpdateUserRole(ctx, sqlc.UpdateUserRoleParams{
		Sub:  sub,
		Role: role,
	})
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(ctx context.Context, sub string) error {
	return s.queries.DeleteUser(ctx, sub)
}

// Helper function to convert sqlc.User to User
func (s *UserService) sqlcUserToUser(user *sqlc.User) *User {
	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	name := ""
	if user.Name != nil {
		name = *user.Name
	}

	return &User{
		Sub:       user.Sub,
		Email:     email,
		Name:      name,
		Role:      user.Role,
		CreatedAt: user.CreatedAt.Time,
		UpdatedAt: user.UpdatedAt.Time,
	}
}
