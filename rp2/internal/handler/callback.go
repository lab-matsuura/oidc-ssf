package handler

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/lab-matsuura/oidc-ssf/rp2/internal/config"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/service"
)

type ErrorPageData struct {
	Title   string
	Message string
	Details string
}

func NewCallbackHandler(cfg *config.Config, oidcService *service.OIDCService, sessionService *service.SessionService, userService *service.UserService, ssfClient *service.SSFClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse query parameters
		query := r.URL.Query()
		code := query.Get("code")
		state := query.Get("state")
		errorParam := query.Get("error")
		errorDesc := query.Get("error_description")

		// Check for OAuth error
		if errorParam != "" {
			renderError(w, "認証エラー", "OIDC Providerから認証エラーが返されました: "+errorParam, errorDesc)
			return
		}

		// Validate required parameters
		if code == "" {
			renderError(w, "パラメータエラー", "認可コードが見つかりません", "OIDC Providerから有効な認可コードが返されませんでした")
			return
		}

		if state == "" {
			renderError(w, "セキュリティエラー", "Stateパラメータが見つかりません", "CSRF攻撃を防ぐためのstateパラメータが不足しています")
			return
		}

		// Validate state parameter (CSRF protection)
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil || stateCookie.Value != state {
			renderError(w, "セキュリティエラー", "Stateパラメータが一致しません", "CSRF攻撃の可能性があります。再度ログインをお試しください")
			return
		}

		// Get code_verifier from cookie for PKCE
		var codeVerifier string
		if cookie, err := r.Cookie("code_verifier"); err == nil {
			codeVerifier = cookie.Value
		}

		// Exchange authorization code for tokens (with PKCE if available)
		tokenResp, err := oidcService.ExchangeCodeForTokensWithPKCE(code, codeVerifier)
		if err != nil {
			log.Printf("Token exchange error: %v", err)
			renderError(w, "トークン取得エラー", "認可コードをトークンに交換できませんでした", err.Error())
			return
		}

		// Validate ID token
		if err := oidcService.ValidateIDToken(tokenResp.IDToken); err != nil {
			log.Printf("ID token validation error: %v", err)
			renderError(w, "トークン検証エラー", "IDトークンの検証に失敗しました", err.Error())
			return
		}

		// Get user info (includes role from IdP)
		userInfo, err := oidcService.GetUserInfo(tokenResp.AccessToken)
		if err != nil {
			log.Printf("UserInfo error: %v", err)
			renderError(w, "ユーザー情報取得エラー", "ユーザー情報の取得に失敗しました", err.Error())
			return
		}

		log.Printf("UserInfo received - sub: %s, role: %s", userInfo.Sub, userInfo.Role)

		// Create or update user in the database with role from UserInfo
		_, err = userService.CreateOrUpdateUser(ctx, userInfo.Sub, userInfo.Email, userInfo.Name, userInfo.Role)
		if err != nil {
			log.Printf("User creation error: %v", err)
			renderError(w, "ユーザー作成エラー", "ユーザー情報の保存に失敗しました", err.Error())
			return
		}

		// Create session - use Sub (subject) as username for consistency with SSF events
		// Session expires in 24 hours
		expiresAt := time.Now().Add(24 * time.Hour)
		session, err := sessionService.CreateSession(
			ctx,
			userInfo.Sub, // Use Sub instead of Name for SSF compatibility
			tokenResp.AccessToken,
			tokenResp.IDToken,
			tokenResp.RefreshToken,
			expiresAt,
		)
		if err != nil {
			log.Printf("Session creation error: %v", err)
			renderError(w, "セッション作成エラー", "セッションの作成に失敗しました", err.Error())
			return
		}

		// Register subject with SSF stream (if SSF client is enabled)
		if ssfClient != nil {
			go func() {
				// Use background context since the HTTP request may complete before this finishes
				bgCtx := context.Background()

				streamID, err := ssfClient.EnsureStream(bgCtx)
				if err != nil {
					log.Printf("SSF: Failed to ensure stream: %v", err)
					return
				}

				subject := &service.Subject{
					Format: "iss_sub",
					Iss:    cfg.IssuerURL,
					Sub:    userInfo.Sub,
				}

				if err := ssfClient.AddSubject(bgCtx, streamID, subject); err != nil {
					log.Printf("SSF: Failed to add subject: %v", err)
					return
				}

				log.Printf("SSF: Successfully registered subject %s for stream %s", userInfo.Sub, streamID)
			}()
		}

		// Set session cookie
		sessionService.SetSessionCookie(w, session.ID)

		// Clear the oauth_state and code_verifier cookies
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "code_verifier",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})

		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func renderError(w http.ResponseWriter, title, message, details string) {
	data := ErrorPageData{
		Title:   title,
		Message: message,
		Details: details,
	}

	tmplPath := filepath.Join("rp2", "templates", "error.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Template parsing error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadRequest)
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Template execution error: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
