package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"golang.org/x/crypto/bcrypt"
)

// ClientsHandler handles OAuth client management
type ClientsHandler struct {
	store     *postgres.PostgresStore
	queries   *sqlc.Queries
	templates *template.Template
}

// NewClientsHandler creates a new clients handler
func NewClientsHandler(store *postgres.PostgresStore, queries *sqlc.Queries, templates *template.Template) *ClientsHandler {
	return &ClientsHandler{
		store:     store,
		queries:   queries,
		templates: templates,
	}
}

// ClientView represents a client for display in templates
type ClientView struct {
	ID            string
	Public        bool
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	CreatedAt     string
	UpdatedAt     string
}

// convertClient converts sqlc.Client to ClientView
func convertClient(c sqlc.Client) ClientView {
	var redirectURIs, grantTypes, responseTypes, scopes []string
	_ = json.Unmarshal(c.RedirectUris, &redirectURIs)
	_ = json.Unmarshal(c.GrantTypes, &grantTypes)
	_ = json.Unmarshal(c.ResponseTypes, &responseTypes)
	_ = json.Unmarshal(c.Scopes, &scopes)

	createdAt := ""
	if c.CreatedAt.Valid {
		createdAt = c.CreatedAt.Time.Format("2006-01-02 15:04")
	}
	updatedAt := ""
	if c.UpdatedAt.Valid {
		updatedAt = c.UpdatedAt.Time.Format("2006-01-02 15:04")
	}

	return ClientView{
		ID:            c.ID,
		Public:        c.Public,
		RedirectURIs:  redirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

func (h *ClientsHandler) baseData(r *http.Request) map[string]any {
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

// List shows all OAuth clients
func (h *ClientsHandler) List(w http.ResponseWriter, r *http.Request) {
	clients, err := h.queries.ListClients(r.Context())
	if err != nil {
		http.Error(w, "Failed to list clients", http.StatusInternalServerError)
		return
	}

	clientViews := make([]ClientView, len(clients))
	for i, c := range clients {
		clientViews[i] = convertClient(c)
	}

	data := h.baseData(r)
	data["Title"] = "OAuth Clients"
	data["Clients"] = clientViews
	data["Message"] = r.URL.Query().Get("message")

	if err := h.templates.ExecuteTemplate(w, "portal_clients_list.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// New shows the create client form
func (h *ClientsHandler) New(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r)
	data["Title"] = "Create New Client"
	data["Client"] = ClientView{
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}

	if err := h.templates.ExecuteTemplate(w, "portal_clients_create.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// Create handles client creation
func (h *ClientsHandler) Create(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		h.showCreateError(w, r, "Client ID is required")
		return
	}

	redirectURIs := r.Form["redirect_uris"]
	grantTypes := r.Form["grant_types"]
	responseTypes := r.Form["response_types"]
	scopes := r.Form["scopes"]
	isPublic := r.FormValue("public") == "on"

	var secret string
	var hashedSecret []byte
	if !isPublic {
		secret = generateSecureSecret(32)
		var err error
		hashedSecret, err = bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash secret", http.StatusInternalServerError)
			return
		}
	}

	redirectURIsJSON, _ := json.Marshal(redirectURIs)
	grantTypesJSON, _ := json.Marshal(grantTypes)
	responseTypesJSON, _ := json.Marshal(responseTypes)
	scopesJSON, _ := json.Marshal(scopes)

	err := h.queries.CreateClient(r.Context(), sqlc.CreateClientParams{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectUris:  redirectURIsJSON,
		GrantTypes:    grantTypesJSON,
		ResponseTypes: responseTypesJSON,
		Scopes:        scopesJSON,
		Public:        isPublic,
	})
	if err != nil {
		h.showCreateError(w, r, "Failed to create client: "+err.Error())
		return
	}

	data := h.baseData(r)
	data["Title"] = "Client Created"
	data["ClientID"] = clientID
	data["ClientSecret"] = secret
	data["IsPublic"] = isPublic

	if err := h.templates.ExecuteTemplate(w, "portal_clients_created.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

func (h *ClientsHandler) showCreateError(w http.ResponseWriter, r *http.Request, message string) {
	data := h.baseData(r)
	data["Title"] = "Create New Client"
	data["Error"] = message
	data["Client"] = ClientView{
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}
	w.WriteHeader(http.StatusBadRequest)
	_ = h.templates.ExecuteTemplate(w, "portal_clients_create.html", data)
}

// Edit shows the edit client form
func (h *ClientsHandler) Edit(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["id"]

	client, err := h.queries.GetClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	data := h.baseData(r)
	data["Title"] = "Edit Client: " + clientID
	data["Client"] = convertClient(client)
	data["Updated"] = r.URL.Query().Get("updated") == "true"

	if err := h.templates.ExecuteTemplate(w, "portal_clients_edit.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// Update handles client updates
func (h *ClientsHandler) Update(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["id"]

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	existing, err := h.queries.GetClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	redirectURIs := r.Form["redirect_uris"]
	grantTypes := r.Form["grant_types"]
	responseTypes := r.Form["response_types"]
	scopes := r.Form["scopes"]
	isPublic := r.FormValue("public") == "on"

	redirectURIsJSON, _ := json.Marshal(redirectURIs)
	grantTypesJSON, _ := json.Marshal(grantTypes)
	responseTypesJSON, _ := json.Marshal(responseTypes)
	scopesJSON, _ := json.Marshal(scopes)

	err = h.queries.UpdateClient(r.Context(), sqlc.UpdateClientParams{
		ID:            clientID,
		Secret:        existing.Secret,
		RedirectUris:  redirectURIsJSON,
		GrantTypes:    grantTypesJSON,
		ResponseTypes: responseTypesJSON,
		Scopes:        scopesJSON,
		Public:        isPublic,
	})
	if err != nil {
		http.Error(w, "Failed to update client", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/clients/"+clientID+"?updated=true", http.StatusSeeOther)
}

// Delete handles client deletion
func (h *ClientsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["id"]

	if err := h.queries.DeleteClient(r.Context(), clientID); err != nil {
		http.Error(w, "Failed to delete client", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/clients?message=Client+deleted+successfully", http.StatusSeeOther)
}

// RegenerateSecret generates a new client secret
func (h *ClientsHandler) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["id"]

	_, err := h.queries.GetClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	newSecret := generateSecureSecret(32)
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(newSecret), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash secret", http.StatusInternalServerError)
		return
	}

	if err := h.queries.UpdateClientSecret(r.Context(), sqlc.UpdateClientSecretParams{
		ID:     clientID,
		Secret: hashedSecret,
	}); err != nil {
		http.Error(w, "Failed to update secret", http.StatusInternalServerError)
		return
	}

	data := h.baseData(r)
	data["Title"] = "Secret Regenerated"
	data["ClientID"] = clientID
	data["ClientSecret"] = newSecret

	if err := h.templates.ExecuteTemplate(w, "portal_clients_secret.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

func generateSecureSecret(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}
