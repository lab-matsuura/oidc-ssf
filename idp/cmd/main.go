package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/handler"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/middleware"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	portalhandler "github.com/lab-matsuura/oidc-ssf/idp/internal/portal/handler"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres"
)

var (
	dbHost                 = flag.String("db-host", getEnv("DB_HOST", "localhost"), "PostgreSQL host")
	dbPort                 = flag.Int("db-port", getEnvInt("DB_PORT", 5432), "PostgreSQL port")
	dbUser                 = flag.String("db-user", getEnv("DB_USER", "postgres"), "PostgreSQL user")
	dbPassword             = flag.String("db-password", getEnv("DB_PASSWORD", "postgres"), "PostgreSQL password")
	dbName                 = flag.String("db-name", getEnv("DB_NAME", "idp"), "PostgreSQL database name")
	dbSSLMode              = flag.String("db-sslmode", getEnv("DB_SSLMODE", "disable"), "PostgreSQL SSL mode")
	issuerURL              = flag.String("issuer-url", getEnv("OIDC_ISSUER_URL", "http://localhost:8080"), "OIDC Issuer URL")
	ssfClientURL           = flag.String("ssf-client-url", getEnv("SSF_CLIENT_URL", "http://localhost:8081"), "SSF Client URL for receiver")
	privateKeyPath         = flag.String("private-key-path", getEnv("RSA_PRIVATE_KEY_PATH", ""), "Path to RSA private key PEM file")
	globalSecret           = flag.String("global-secret", getEnv("FOSITE_GLOBAL_SECRET", ""), "Secret for HMAC operations (min 32 chars)")
	seedTestClients        = flag.Bool("seed-test-clients", getEnvBool("SEED_TEST_CLIENTS", true), "Seed test client on startup")
	seedConformanceClients = flag.Bool("seed-conformance-clients", getEnvBool("SEED_CONFORMANCE_CLIENTS", false), "Seed OIDC conformance suite clients on startup")
	ssfDefaultSubjects     = flag.String("ssf-default-subjects", getEnv("SSF_DEFAULT_SUBJECTS", "NONE"), "SSF default_subjects setting (ALL or NONE)")
	ssfParallelDelivery    = flag.Bool("ssf-parallel-delivery", getEnvBool("SSF_PARALLEL_DELIVERY", true), "Enable parallel event delivery")
	ssfQueueInterval       = flag.Duration("ssf-queue-interval", getEnvDuration("SSF_QUEUE_INTERVAL", 10*time.Second), "SSF event queue processing interval")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	// Configure provider with PostgreSQL
	cfg := provider.Config{
		PostgresConfig: postgres.Config{
			Host:     *dbHost,
			Port:     *dbPort,
			User:     *dbUser,
			Password: *dbPassword,
			DBName:   *dbName,
			SSLMode:  *dbSSLMode,
			MaxConns: 10,
		},
		IssuerURL:              *issuerURL,
		PrivateKeyPath:         *privateKeyPath,
		GlobalSecret:           *globalSecret,
		SeedTestClients:        *seedTestClients,
		SeedConformanceClients: *seedConformanceClients,
	}

	log.Printf("Connecting to PostgreSQL: %s:%d/%s", *dbHost, *dbPort, *dbName)

	// Initialize OIDC provider
	oidcProvider, err := provider.NewOIDCProvider(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize OIDC provider: %v", err)
	}

	log.Printf("OIDC Provider initialized with PostgreSQL storage (Issuer: %s)", *issuerURL)

	// Load templates with custom functions
	templatesPath := filepath.Join("idp", "templates", "*.html")
	templates, err := template.New("").Funcs(template.FuncMap{
		"formatValue": func(v interface{}) template.HTML {
			return template.HTML(fmt.Sprintf("%v", v))
		},
		"contains": func(slice []string, item string) bool {
			for _, s := range slice {
				if s == item {
					return true
				}
			}
			return false
		},
		"iterate": func(count int) []int {
			result := make([]int, count)
			for i := range result {
				result[i] = i
			}
			return result
		},
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
	}).ParseGlob(templatesPath)
	if err != nil {
		log.Printf("Warning: Failed to load templates: %v", err)
		// Create empty template for development
		templates = template.New("")
	}

	// Setup routes
	router := mux.NewRouter()

	// Setup middleware - redirects to /setup if no owner exists
	setupMiddleware := middleware.NewSetupRequired(oidcProvider.UserService)
	router.Use(setupMiddleware.Middleware)

	// Initial setup endpoint
	setupHandler := handler.NewSetupHandler(oidcProvider.UserService, templates)
	router.HandleFunc("/setup", setupHandler.ShowSetup).Methods("GET")
	router.HandleFunc("/setup", setupHandler.ProcessSetup).Methods("POST")

	// OIDC endpoints
	router.HandleFunc("/authorize", handler.NewAuthorizeHandler(oidcProvider)).Methods("GET", "POST")
	router.HandleFunc("/token", handler.NewTokenHandler(oidcProvider)).Methods("POST")
	router.HandleFunc("/userinfo", handler.NewUserInfoHandler(oidcProvider)).Methods("GET", "POST")
	router.HandleFunc("/jwks", handler.NewJWKSHandler(oidcProvider)).Methods("GET")
	router.HandleFunc("/.well-known/jwks.json", handler.NewJWKSHandler(oidcProvider)).Methods("GET")

	// OpenID Configuration endpoint
	router.HandleFunc("/.well-known/openid-configuration", handler.NewDiscoveryHandler(oidcProvider)).Methods("GET")

	// User registration endpoint
	registerHandler := handler.NewRegisterHandler(oidcProvider.UserService, templates)
	router.Handle("/register", registerHandler).Methods("GET", "POST")

	// SSF API endpoints (spec-compliant)
	ssfAPIConfig := handler.SSFAPIConfig{
		DefaultSubjects:  *ssfDefaultSubjects,
		ParallelDelivery: *ssfParallelDelivery,
	}
	ssfAPIHandler := handler.NewSSFAPIHandler(oidcProvider, oidcProvider.Queries, *issuerURL, *ssfClientURL, ssfAPIConfig)
	ssfAPIHandler.RegisterRoutes(router)

	// Load existing streams from database
	if err := ssfAPIHandler.LoadStreamsFromDB(ctx); err != nil {
		log.Printf("Warning: Failed to load SSF streams from database: %v", err)
	}

	// Start DB-based event queue processor
	ssfAPIHandler.StartDBQueueProcessor(ctx, *ssfQueueInterval)
	log.Printf("SSF: DB-based event queue processor started (interval: %v)", *ssfQueueInterval)

	log.Printf("SSF configured (Issuer: %s, Client: %s)", *issuerURL, *ssfClientURL)

	// Portal middleware and handlers (unified admin + user portal)
	portalMiddleware := portal.NewMiddleware(oidcProvider.Queries)
	portalLoginHandler := portalhandler.NewLoginHandler(oidcProvider.Queries, templates, portalMiddleware)
	portalLoginHandler.SetSSFAPIHandler(ssfAPIHandler) // Enable Single Logout (SLO) via SSF
	dashboardHandler := portalhandler.NewDashboardHandler(oidcProvider.Queries, templates)
	profileHandler := portalhandler.NewProfileHandler(oidcProvider.Queries, templates)
	clientsHandler := portalhandler.NewClientsHandler(oidcProvider.Storage, oidcProvider.Queries, templates)
	usersHandler := portalhandler.NewUsersHandler(oidcProvider.Queries, templates, ssfAPIHandler)
	ssfHandler := portalhandler.NewSSFHandler(oidcProvider.Queries, templates, *issuerURL, oidcProvider.PrivateKey, oidcProvider.KeyID)
	ssfHandler.SetSSFAPIHandler(ssfAPIHandler) // Enable proper test event delivery

	// Unified login page (handles both OIDC and portal login)
	router.HandleFunc("/login", portalLoginHandler.ShowLogin).Methods("GET")
	router.HandleFunc("/login", portalLoginHandler.ProcessLogin).Methods("POST")
	router.HandleFunc("/logout", portalLoginHandler.Logout).Methods("GET", "POST")

	// Portal routes (all authenticated users)
	portalRouter := router.PathPrefix("/portal").Subrouter()
	portalRouter.Use(portalMiddleware.RequireAuth)

	// Dashboard (all users)
	portalRouter.HandleFunc("", dashboardHandler.Index).Methods("GET")
	portalRouter.HandleFunc("/", dashboardHandler.Index).Methods("GET")

	// Profile (all users)
	portalRouter.HandleFunc("/profile", profileHandler.Show).Methods("GET")
	portalRouter.HandleFunc("/profile/display-name", profileHandler.UpdateDisplayName).Methods("POST")

	// Admin-only routes (clients, users, ssf management)
	adminRouter := portalRouter.PathPrefix("").Subrouter()
	adminRouter.Use(portalMiddleware.RequireAdmin)

	// Client management (admin only)
	adminRouter.HandleFunc("/clients", clientsHandler.List).Methods("GET")
	adminRouter.HandleFunc("/clients/new", clientsHandler.New).Methods("GET")
	adminRouter.HandleFunc("/clients", clientsHandler.Create).Methods("POST")
	adminRouter.HandleFunc("/clients/{id}", clientsHandler.Edit).Methods("GET")
	adminRouter.HandleFunc("/clients/{id}", clientsHandler.Update).Methods("POST")
	adminRouter.HandleFunc("/clients/{id}/delete", clientsHandler.Delete).Methods("POST")
	adminRouter.HandleFunc("/clients/{id}/regenerate", clientsHandler.RegenerateSecret).Methods("POST")

	// User management (admin only)
	adminRouter.HandleFunc("/users", usersHandler.List).Methods("GET")
	adminRouter.HandleFunc("/users/create", usersHandler.ShowCreateForm).Methods("GET")
	adminRouter.HandleFunc("/users/create", usersHandler.Create).Methods("POST")
	adminRouter.HandleFunc("/users/{id}", usersHandler.Detail).Methods("GET")
	adminRouter.HandleFunc("/users/{id}/status", usersHandler.UpdateStatus).Methods("POST")
	adminRouter.HandleFunc("/users/{id}/role", usersHandler.UpdateRole).Methods("POST")

	// SSF Stream management (admin only)
	adminRouter.HandleFunc("/ssf", ssfHandler.List).Methods("GET")
	adminRouter.HandleFunc("/ssf/new", ssfHandler.New).Methods("GET")
	adminRouter.HandleFunc("/ssf/new", ssfHandler.Create).Methods("POST")
	adminRouter.HandleFunc("/ssf/log", ssfHandler.EventLogs).Methods("GET")
	adminRouter.HandleFunc("/ssf/{id}", ssfHandler.Edit).Methods("GET")
	adminRouter.HandleFunc("/ssf/{id}", ssfHandler.Update).Methods("POST")
	adminRouter.HandleFunc("/ssf/{id}/delete", ssfHandler.Delete).Methods("POST")
	adminRouter.HandleFunc("/ssf/{id}/status", ssfHandler.UpdateStatus).Methods("POST")
	adminRouter.HandleFunc("/ssf/{id}/verify", ssfHandler.SendVerification).Methods("POST")
	adminRouter.HandleFunc("/ssf/{id}/test-event", ssfHandler.SendTestEvent).Methods("POST")

	log.Println("Portal enabled at /portal (login at /login)")

	log.Println("Starting OIDC server with SSF support on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt gets environment variable as int with default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

// getEnvBool gets environment variable as bool with default value
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}
