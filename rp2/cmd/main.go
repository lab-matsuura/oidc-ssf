package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/config"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/handler"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/service"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/storage/postgres"
)

func main() {
	// Initialize configuration
	cfg := config.NewConfig()

	// Initialize database connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbConfig := postgres.Config{
		Host:     getEnv("RP2_DB_HOST", "localhost"),
		Port:     getEnvInt("RP2_DB_PORT", 5432),
		User:     getEnv("RP2_DB_USER", "postgres"),
		Password: getEnv("RP2_DB_PASSWORD", "postgres"),
		DBName:   getEnv("RP2_DB_NAME", "rp2"),
		SSLMode:  getEnv("RP2_DB_SSLMODE", "disable"),
		MaxConns: int32(getEnvInt("RP2_DB_MAX_CONNS", 10)),
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

	// Initialize SSF client and poller (Poll-based delivery, RFC 8936)
	var ssfClient *service.SSFClient
	var ssfPoller *service.SSFPoller

	if getEnv("SSF_ENABLED", "true") == "true" {
		ssfClient = service.NewSSFClient(cfg, queries)
		log.Printf("SSF Client enabled (Poll-based delivery, mode: %s)", cfg.SSFPollMode)

		// Start the SSF Poller
		ssfPoller = service.NewSSFPoller(cfg, ssfClient, sessionService, userService)
		ssfPoller.Start(ctx)
		log.Printf("SSF Poller started with interval: %v", cfg.SSFPollInterval)
	} else {
		log.Printf("SSF Client disabled")
	}

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

	// Note: No /ssf/receiver endpoint - RP2 uses Poll-based delivery (RFC 8936)

	// Use PORT from environment (Cloud Run requirement) or default to 8082
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	// Handle graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		if ssfPoller != nil {
			ssfPoller.Stop()
		}
		cancel()
		os.Exit(0)
	}()

	log.Printf("Starting RP2 (Poll-based SSF) on :%s", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
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
