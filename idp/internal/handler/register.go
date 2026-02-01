package handler

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/user"
)

// RegisterHandler handles user registration
type RegisterHandler struct {
	userService *user.Service
	templates   *template.Template
}

// NewRegisterHandler creates a new registration handler
func NewRegisterHandler(userService *user.Service, templates *template.Template) *RegisterHandler {
	return &RegisterHandler{
		userService: userService,
		templates:   templates,
	}
}

// ServeHTTP handles both GET (show form) and POST (process registration)
func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.showRegistrationForm(w, r)
	case http.MethodPost:
		h.handleRegistration(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *RegisterHandler) showRegistrationForm(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Register - OIDC Provider",
	}

	if err := h.templates.ExecuteTemplate(w, "register.html", data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		return
	}
}

func (h *RegisterHandler) handleRegistration(w http.ResponseWriter, r *http.Request) {
	var username, email, password, displayName string

	// Check if request is JSON or form data
	contentType := r.Header.Get("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")

	if isJSON {
		// Parse JSON body
		var reqBody struct {
			Username    string `json:"username"`
			Email       string `json:"email"`
			Password    string `json:"password"`
			DisplayName string `json:"display_name"`
		}

		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "Invalid JSON data", http.StatusBadRequest)
			return
		}

		username = reqBody.Username
		email = reqBody.Email
		password = reqBody.Password
		displayName = reqBody.DisplayName
	} else {
		// Parse form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		username = r.FormValue("username")
		email = r.FormValue("email")
		password = r.FormValue("password")
		displayName = r.FormValue("display_name")
	}

	// Validate inputs
	if username == "" || email == "" {
		if isJSON {
			http.Error(w, "Username and email are required", http.StatusBadRequest)
		} else {
			h.showError(w, "Username and email are required")
		}
		return
	}

	// Create user
	newUser, err := h.userService.CreateUser(r.Context(), username, email, password, displayName)
	if err != nil {
		if err == user.ErrUserAlreadyExists {
			if isJSON {
				http.Error(w, "User already exists", http.StatusBadRequest)
			} else {
				h.showError(w, "User already exists")
			}
			return
		}
		if err == user.ErrWeakPassword {
			if isJSON {
				http.Error(w, "Password is too weak (minimum 8 characters)", http.StatusBadRequest)
			} else {
				h.showError(w, "Password is too weak (minimum 8 characters)")
			}
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// For JSON requests, create a session and return success
	if isJSON {
		// Extract UUID bytes from pgtype.UUID
		if !newUser.ID.Valid {
			log.Printf("User ID is not valid")
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		// Convert pgtype.UUID to uuid.UUID
		userID, err := uuid.FromBytes(newUser.ID.Bytes[:])
		if err != nil {
			log.Printf("Failed to convert user ID: %v", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		// Create a simple authentication session
		// Store user ID in session cookie for WebAuthn registration
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_session",
			Value:    userID.String(),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   3600, // 1 hour for registration flow
		})

		log.Printf("Created auth session for user: %s", userID.String())

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("User created successfully"))
		return
	}

	// For form submissions, redirect to login
	http.Redirect(w, r, "/login?registered=true", http.StatusSeeOther)
}

func (h *RegisterHandler) showError(w http.ResponseWriter, message string) {
	data := map[string]interface{}{
		"Title": "Registration Error",
		"Error": message,
	}

	w.WriteHeader(http.StatusBadRequest)
	if err := h.templates.ExecuteTemplate(w, "register.html", data); err != nil {
		http.Error(w, message, http.StatusBadRequest)
	}
}
