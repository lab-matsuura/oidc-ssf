package handler

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/handler"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
	"golang.org/x/crypto/bcrypt"
)

// UsersHandler handles user management
type UsersHandler struct {
	queries       *sqlc.Queries
	templates     *template.Template
	ssfAPIHandler *handler.SSFAPIHandler
}

// NewUsersHandler creates a new users handler
func NewUsersHandler(queries *sqlc.Queries, templates *template.Template, ssfAPIHandler *handler.SSFAPIHandler) *UsersHandler {
	return &UsersHandler{
		queries:       queries,
		templates:     templates,
		ssfAPIHandler: ssfAPIHandler,
	}
}

// UserView represents a user for display in templates
type UserView struct {
	ID            string
	Username      string
	Email         string
	EmailVerified bool
	DisplayName   string
	Role          string
	AccountStatus string
	CreatedAt     string
	UpdatedAt     string
	LastLoginAt   string
}

func convertUser(u sqlc.User) UserView {
	displayName := ""
	if u.DisplayName != nil {
		displayName = *u.DisplayName
	}

	createdAt := ""
	if u.CreatedAt.Valid {
		createdAt = u.CreatedAt.Time.Format("2006-01-02 15:04")
	}
	updatedAt := ""
	if u.UpdatedAt.Valid {
		updatedAt = u.UpdatedAt.Time.Format("2006-01-02 15:04")
	}
	lastLoginAt := ""
	if u.LastLoginAt.Valid {
		lastLoginAt = u.LastLoginAt.Time.Format("2006-01-02 15:04")
	}

	userID := ""
	if u.ID.Valid {
		userID = uuid.UUID(u.ID.Bytes).String()
	}

	return UserView{
		ID:            userID,
		Username:      u.Username,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		DisplayName:   displayName,
		Role:          u.Role,
		AccountStatus: u.AccountStatus,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		LastLoginAt:   lastLoginAt,
	}
}

func (h *UsersHandler) baseData(r *http.Request) map[string]any {
	user := portal.GetCurrentUser(r.Context())
	displayName := user.Username
	if user.DisplayName != nil && *user.DisplayName != "" {
		displayName = *user.DisplayName
	}
	return map[string]any{
		"User":        user,
		"DisplayName": displayName,
		"IsAdmin":     portal.IsAdmin(r.Context()),
	}
}

// List shows all users with pagination
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := int32(20)
	offset := int32((page - 1) * 20)

	search := r.URL.Query().Get("q")
	statusFilter := r.URL.Query().Get("status")

	var users []sqlc.User
	var err error

	if search != "" {
		users, err = h.queries.SearchUsers(r.Context(), sqlc.SearchUsersParams{
			Username: "%" + search + "%",
			Limit:    limit,
			Offset:   offset,
		})
	} else if statusFilter != "" {
		users, err = h.queries.ListUsersByStatus(r.Context(), sqlc.ListUsersByStatusParams{
			AccountStatus: statusFilter,
			Limit:         limit,
			Offset:        offset,
		})
	} else {
		users, err = h.queries.ListUsers(r.Context(), sqlc.ListUsersParams{
			Limit:  limit,
			Offset: offset,
		})
	}

	if err != nil {
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	total, _ := h.queries.CountUsers(r.Context())

	userViews := make([]UserView, len(users))
	for i, u := range users {
		userViews[i] = convertUser(u)
	}

	totalPages := int((total + int64(limit) - 1) / int64(limit))

	pages := make([]int, totalPages)
	for i := range pages {
		pages[i] = i + 1
	}

	data := h.baseData(r)
	data["Title"] = "Users"
	data["Users"] = userViews
	data["CurrentPage"] = page
	data["TotalPages"] = totalPages
	data["TotalUsers"] = total
	data["Search"] = search
	data["StatusFilter"] = statusFilter
	data["Message"] = r.URL.Query().Get("message")
	data["ShowPagination"] = totalPages > 1
	data["HasPrevPage"] = page > 1
	data["HasNextPage"] = page < totalPages
	data["PrevPage"] = page - 1
	data["NextPage"] = page + 1
	data["Pages"] = pages

	if err := h.templates.ExecuteTemplate(w, "portal_users_list.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// Detail shows user details
func (h *UsersHandler) Detail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}

	user, err := h.queries.GetUserByIDIncludeInactive(r.Context(), pgUserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	data := h.baseData(r)
	data["Title"] = "User: " + user.Username
	data["TargetUser"] = convertUser(user)
	data["IsOwner"] = user.Role == "owner"
	data["Updated"] = r.URL.Query().Get("updated") == "true"

	if err := h.templates.ExecuteTemplate(w, "portal_users_detail.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// UpdateStatus handles user status changes
func (h *UsersHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	newStatus := r.FormValue("status")
	if newStatus != "active" && newStatus != "suspended" && newStatus != "deleted" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}

	user, err := h.queries.GetUserByIDIncludeInactive(r.Context(), pgUserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Role == "owner" {
		http.Error(w, "Cannot modify owner account status", http.StatusForbidden)
		return
	}

	if err := h.queries.UpdateUserAccountStatus(r.Context(), sqlc.UpdateUserAccountStatusParams{
		ID:            pgUserID,
		AccountStatus: newStatus,
	}); err != nil {
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	if h.ssfAPIHandler != nil {
		// Use UUID as subject identifier (RFC 9493 iss_sub format)
		userUUID := uuid.UUID(user.ID.Bytes).String()
		h.emitStatusChangeEvent(userUUID, newStatus)
	}

	http.Redirect(w, r, "/portal/users/"+userIDStr+"?updated=true", http.StatusSeeOther)
}

func (h *UsersHandler) emitStatusChangeEvent(userID string, newStatus string) {
	var eventType string
	var eventData map[string]interface{}

	switch newStatus {
	case "suspended":
		eventType = ssf.EventTypeAccountDisabled
		eventData = map[string]interface{}{
			"reason_admin": map[string]interface{}{
				"en": "Account suspended by administrator",
			},
		}
	case "deleted":
		eventType = ssf.EventTypeAccountPurged
		eventData = map[string]interface{}{
			"reason_admin": map[string]interface{}{
				"en": "Account deleted by administrator",
			},
		}
	case "active":
		eventType = ssf.EventTypeAccountEnabled
		eventData = map[string]interface{}{}
	default:
		return
	}

	// Emit SSF event asynchronously (don't block HTTP response)
	go func() {
		ctx := context.Background()
		result, err := h.ssfAPIHandler.EmitEventForSubject(ctx, eventType, userID, eventData)
		if err != nil {
			log.Printf("SSF: Failed to emit event for user %s: %v", userID, err)
			return
		}

		log.Printf("SSF: Emitted %s event for user %s to %d streams (success: %d, failed: %d, duration: %dms)",
			eventType, userID, result.StreamCount, result.SuccessCount, result.FailureCount, result.DurationMs)
	}()
}

// UpdateRole handles user role changes
func (h *UsersHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	newRole := r.FormValue("role")
	if newRole != "user" && newRole != "admin" {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}

	pgUserID := pgtype.UUID{Bytes: userID, Valid: true}

	user, err := h.queries.GetUserByIDIncludeInactive(r.Context(), pgUserID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Role == "owner" {
		http.Error(w, "Cannot modify owner account role", http.StatusForbidden)
		return
	}

	if err := h.queries.UpdateUserRole(r.Context(), sqlc.UpdateUserRoleParams{
		ID:   pgUserID,
		Role: newRole,
	}); err != nil {
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	if h.ssfAPIHandler != nil {
		// Use UUID as subject identifier (RFC 9493 iss_sub format)
		userUUID := uuid.UUID(user.ID.Bytes).String()
		h.emitRoleChangeEvent(userUUID, newRole)
	}

	http.Redirect(w, r, "/portal/users/"+userIDStr+"?updated=true", http.StatusSeeOther)
}

func (h *UsersHandler) emitRoleChangeEvent(userID string, newRole string) {
	eventData := map[string]interface{}{
		"claims": map[string]interface{}{
			"role": newRole,
		},
	}

	// Emit SSF event asynchronously (don't block HTTP response)
	go func() {
		ctx := context.Background()
		result, err := h.ssfAPIHandler.EmitEventForSubject(ctx, ssf.EventTypeTokenClaimsChange, userID, eventData)
		if err != nil {
			log.Printf("SSF: Failed to emit token-claims-change event for user %s: %v", userID, err)
			return
		}

		log.Printf("SSF: Emitted token-claims-change event for user %s (role=%s) to %d streams (success: %d, failed: %d, duration: %dms)",
			userID, newRole, result.StreamCount, result.SuccessCount, result.FailureCount, result.DurationMs)
	}()
}

// ShowCreateForm displays the user creation form
func (h *UsersHandler) ShowCreateForm(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r)
	data["Title"] = "Create New User"

	if err := h.templates.ExecuteTemplate(w, "portal_users_create.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// Create handles the user creation form submission
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderCreateFormWithError(w, r, "Failed to parse form")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	email := strings.TrimSpace(r.FormValue("email"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	role := r.FormValue("role")

	if username == "" {
		h.renderCreateFormWithError(w, r, "Username is required")
		return
	}

	if len(username) < 3 {
		h.renderCreateFormWithError(w, r, "Username must be at least 3 characters")
		return
	}

	if password == "" {
		h.renderCreateFormWithError(w, r, "Password is required")
		return
	}

	if len(password) < 6 {
		h.renderCreateFormWithError(w, r, "Password must be at least 6 characters")
		return
	}

	if email == "" {
		h.renderCreateFormWithError(w, r, "Email is required")
		return
	}

	if role != "user" && role != "admin" {
		role = "user"
	}

	usernameExists, err := h.queries.CheckUsernameExists(r.Context(), username)
	if err != nil {
		h.renderCreateFormWithError(w, r, "Failed to check username: "+err.Error())
		return
	}
	if usernameExists {
		h.renderCreateFormWithError(w, r, "Username already exists")
		return
	}

	emailExists, err := h.queries.CheckEmailExists(r.Context(), email)
	if err != nil {
		h.renderCreateFormWithError(w, r, "Failed to check email: "+err.Error())
		return
	}
	if emailExists {
		h.renderCreateFormWithError(w, r, "Email already exists")
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.renderCreateFormWithError(w, r, "Failed to hash password")
		return
	}

	var displayNamePtr *string
	if displayName != "" {
		displayNamePtr = &displayName
	}

	_, err = h.queries.CreateUserByAdmin(r.Context(), sqlc.CreateUserByAdminParams{
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		DisplayName:  displayNamePtr,
		Role:         role,
	})
	if err != nil {
		h.renderCreateFormWithError(w, r, "Failed to create user: "+err.Error())
		return
	}

	http.Redirect(w, r, "/portal/users?message=User+created+successfully", http.StatusSeeOther)
}

func (h *UsersHandler) renderCreateFormWithError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	data := h.baseData(r)
	data["Title"] = "Create New User"
	data["Error"] = errorMsg
	data["FormUsername"] = r.FormValue("username")
	data["FormEmail"] = r.FormValue("email")
	data["FormDisplayName"] = r.FormValue("display_name")
	data["FormRole"] = r.FormValue("role")

	if err := h.templates.ExecuteTemplate(w, "portal_users_create.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}
