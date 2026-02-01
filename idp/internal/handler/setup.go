package handler

import (
	"html/template"
	"log"
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/user"
)

// SetupHandler handles initial system setup
type SetupHandler struct {
	userService *user.Service
	templates   *template.Template
}

// NewSetupHandler creates a new setup handler
func NewSetupHandler(userService *user.Service, templates *template.Template) *SetupHandler {
	return &SetupHandler{
		userService: userService,
		templates:   templates,
	}
}

// SetupData represents the data passed to the setup template
type SetupData struct {
	Error   string
	Success bool
}

// ShowSetup displays the setup form
func (h *SetupHandler) ShowSetup(w http.ResponseWriter, r *http.Request) {
	// Check if owner already exists
	hasOwner, err := h.userService.HasOwner(r.Context())
	if err != nil {
		log.Printf("Error checking owner existence: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// If owner exists, redirect to admin login
	if hasOwner {
		http.Redirect(w, r, "/portal", http.StatusSeeOther)
		return
	}

	// Show setup form
	data := SetupData{}
	if err := h.templates.ExecuteTemplate(w, "setup.html", data); err != nil {
		log.Printf("Error rendering setup template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ProcessSetup handles the setup form submission
func (h *SetupHandler) ProcessSetup(w http.ResponseWriter, r *http.Request) {
	// Check if owner already exists
	hasOwner, err := h.userService.HasOwner(r.Context())
	if err != nil {
		log.Printf("Error checking owner existence: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if hasOwner {
		http.Redirect(w, r, "/portal", http.StatusSeeOther)
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		h.renderSetupWithError(w, "Invalid form data")
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")
	displayName := r.FormValue("display_name")

	// Validate inputs
	if username == "" || email == "" || password == "" {
		h.renderSetupWithError(w, "Username, email, and password are required")
		return
	}

	if password != passwordConfirm {
		h.renderSetupWithError(w, "Passwords do not match")
		return
	}

	if len(password) < 8 {
		h.renderSetupWithError(w, "Password must be at least 8 characters")
		return
	}

	// Create owner user
	_, err = h.userService.CreateOwner(r.Context(), username, email, password, displayName)
	if err != nil {
		log.Printf("Error creating owner: %v", err)
		if err == user.ErrOwnerAlreadyExists {
			http.Redirect(w, r, "/portal", http.StatusSeeOther)
			return
		}
		h.renderSetupWithError(w, "Failed to create owner: "+err.Error())
		return
	}

	log.Printf("Owner user created: %s", username)

	// Redirect to admin login
	http.Redirect(w, r, "/portal", http.StatusSeeOther)
}

func (h *SetupHandler) renderSetupWithError(w http.ResponseWriter, errMsg string) {
	data := SetupData{Error: errMsg}
	if err := h.templates.ExecuteTemplate(w, "setup.html", data); err != nil {
		log.Printf("Error rendering setup template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
