package handler

import (
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/lab-matsuura/oidc-ssf/rp/internal/service"
)

type HomePageData struct {
	IsLoggedIn bool
	User       *service.UserInfo
}

func NewHomeHandler(sessionService *service.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, isLoggedIn := sessionService.GetSessionFromRequest(r)

		data := HomePageData{
			IsLoggedIn: isLoggedIn,
		}

		if isLoggedIn && session != nil {
			data.User = &session.UserInfo
		}

		// Load template
		tmplPath := filepath.Join("rp", "templates", "home.html")
		tmpl, err := template.ParseFiles(tmplPath)
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
