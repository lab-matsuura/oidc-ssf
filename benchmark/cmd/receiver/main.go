package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lab-matsuura/oidc-ssf/benchmark/internal/receiver"
)

func main() {
	port := flag.Int("port", 9090, "Port to listen on")
	logPath := flag.String("log", "", "Path to log file (empty for stdout)")
	flag.Parse()

	handler, err := receiver.NewHandler(*logPath)
	if err != nil {
		log.Fatalf("Failed to create handler: %v", err)
	}
	defer func() { _ = handler.Close() }()

	mux := http.NewServeMux()
	mux.Handle("/rp/", handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "OK - received: %d", handler.GetReceivedCount())
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		_ = server.Close()
	}()

	log.Printf("Mock SET Receiver listening on :%d", *port)
	if *logPath != "" {
		log.Printf("Logging to file: %s", *logPath)
	} else {
		log.Printf("Logging to stdout (Cloud Logging mode)")
	}
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Printf("Total received: %d", handler.GetReceivedCount())
}
