package handler

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"github.com/lab-matsuura/oidc-ssf/rp2/internal/service"
)

type ProfilePageData struct {
	UserInfo      *service.UserInfo
	Session       *service.UserSession
	IDTokenClaims map[string]interface{}
}

func NewProfileHandler(sessionService *service.SessionService, oidcService *service.OIDCService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if user is logged in
		session, isLoggedIn := sessionService.GetSessionFromRequest(r)
		if !isLoggedIn {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Parse ID token claims for display
		var idTokenClaims map[string]interface{}
		if session.IDToken != "" {
			claims, err := oidcService.ParseIDTokenClaims(session.IDToken)
			if err != nil {
				log.Printf("Failed to parse ID token claims: %v", err)
				// Continue without claims display
			} else {
				idTokenClaims = claims
			}
		}

		data := ProfilePageData{
			UserInfo:      &session.UserInfo,
			Session:       session,
			IDTokenClaims: idTokenClaims,
		}

		// Load template with custom functions
		tmplPath := filepath.Join("rp2", "templates", "profile.html")
		tmpl, err := template.New("profile.html").Funcs(template.FuncMap{
			"formatValue": func(v interface{}) template.HTML {
				return template.HTML(fmt.Sprintf("%v", v))
			},
		}).ParseFiles(tmplPath)
		if err != nil {
			http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Execute template
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
