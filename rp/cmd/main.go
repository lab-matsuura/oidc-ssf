package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/config"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/handler"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/service"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/storage/postgres"
)

func main() {
	// Initialize configuration
	cfg := config.NewConfig()

	// Initialize database connection
	ctx := context.Background()
	dbConfig := postgres.Config{
		Host:     getEnv("RP_DB_HOST", "localhost"),
		Port:     getEnvInt("RP_DB_PORT", 5432),
		User:     getEnv("RP_DB_USER", "postgres"),
		Password: getEnv("RP_DB_PASSWORD", "postgres"),
		DBName:   getEnv("RP_DB_NAME", "rp"),
		SSLMode:  getEnv("RP_DB_SSLMODE", "disable"),
		MaxConns: int32(getEnvInt("RP_DB_MAX_CONNS", 10)),
	}

	pool, err := postgres.NewPool(ctx, dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()
	log.Printf("Connected to database: %s", dbConfig.DBName)

	// Initialize queries
	queries := postgres.NewQueries(pool)

	// Initialize services
	sessionService := service.NewSessionService(queries, cfg.SecureCookies)
	userService := service.NewUserService(queries)
	oidcService := service.NewOIDCService(cfg)

	// Initialize SSF client (optional, controlled by SSF_ENABLED env var)
	var ssfClient *service.SSFClient
	if getEnv("SSF_ENABLED", "true") == "true" {
		ssfClient = service.NewSSFClient(cfg, queries)
		log.Printf("SSF Client enabled")
	} else {
		log.Printf("SSF Client disabled")
	}

	// Initialize SSF handler with session service and user service
	ssfHandler := handler.NewSSFHandler(sessionService, userService)

	// Setup routes
	router := mux.NewRouter()

	// Static file serving for CSS/JS if needed
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// OIDC Client endpoints
	router.HandleFunc("/", handler.NewHomeHandler(sessionService)).Methods("GET")
	router.HandleFunc("/login", handler.NewLoginHandler(cfg, sessionService)).Methods("GET")
	router.HandleFunc("/callback", handler.NewCallbackHandler(cfg, oidcService, sessionService, userService, ssfClient)).Methods("GET")
	router.HandleFunc("/profile", handler.NewProfileHandler(sessionService, oidcService)).Methods("GET")
	router.HandleFunc("/logout", handler.NewLogoutHandler(sessionService)).Methods("GET")

	// SSF endpoints
	ssfHandler.RegisterRoutes(router)

	// Use PORT from environment (Cloud Run requirement) or default to 8081
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Starting OIDC Client with SSF support on :%s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Failed to start client server: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
