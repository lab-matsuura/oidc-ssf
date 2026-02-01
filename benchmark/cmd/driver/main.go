package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lab-matsuura/oidc-ssf/benchmark/internal/driver"
	_ "github.com/lib/pq"
)

func main() {
	// Subcommands
	setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
	emitCmd := flag.NewFlagSet("emit", flag.ExitOnError)
	pollCmd := flag.NewFlagSet("poll", flag.ExitOnError)
	analyzeCmd := flag.NewFlagSet("analyze", flag.ExitOnError)
	cleanupCmd := flag.NewFlagSet("cleanup", flag.ExitOnError)

	// Setup flags
	setupRPs := setupCmd.Int("rps", 5, "Number of RPs")
	setupUsers := setupCmd.Int("users", 100, "Number of users")
	setupReceiverURL := setupCmd.String("receiver-url", "http://localhost:9090", "Mock receiver URL")
	setupMode := setupCmd.String("mode", "push", "Delivery mode: push or poll")
	setupDBURL := setupCmd.String("db", "postgres://postgres:postgres@localhost:5432/idp?sslmode=disable", "Database URL")
	setupIdPURL := setupCmd.String("idp-url", "http://localhost:8080", "IdP URL for token acquisition")
	setupTokensFile := setupCmd.String("tokens-file", "benchmark/results/tokens.json", "Path to save tokens")

	// Emit flags
	emitIdPURL := emitCmd.String("idp-url", "http://localhost:8080", "IdP URL")
	emitDBURL := emitCmd.String("db", "postgres://postgres:postgres@localhost:5432/idp?sslmode=disable", "Database URL")
	emitConcurrency := emitCmd.Int("concurrency", 10, "Concurrency level")

	// Poll flags
	pollIdPURL := pollCmd.String("idp-url", "http://localhost:8080", "IdP URL")
	pollTokensFile := pollCmd.String("tokens", "benchmark/results/tokens.json", "Tokens file path")
	pollTimeout := pollCmd.Duration("timeout", 60*time.Second, "Poll timeout")
	pollLogPath := pollCmd.String("log", "benchmark/results/poll.jsonl", "Log file path")

	// Analyze flags
	analyzeLogPath := analyzeCmd.String("log", "benchmark/results/receive.jsonl", "Log file path")
	analyzeOutputPath := analyzeCmd.String("output", "", "Output JSON path (optional)")

	// Cleanup flags
	cleanupDBURL := cleanupCmd.String("db", "postgres://postgres:postgres@localhost:5432/idp?sslmode=disable", "Database URL")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "setup":
		_ = setupCmd.Parse(os.Args[2:])
		runSetup(*setupDBURL, *setupIdPURL, *setupRPs, *setupUsers, *setupReceiverURL, *setupMode, *setupTokensFile)

	case "emit":
		_ = emitCmd.Parse(os.Args[2:])
		runEmit(*emitDBURL, *emitIdPURL, *emitConcurrency)

	case "poll":
		_ = pollCmd.Parse(os.Args[2:])
		runPoll(*pollIdPURL, *pollTokensFile, *pollTimeout, *pollLogPath)

	case "analyze":
		_ = analyzeCmd.Parse(os.Args[2:])
		runAnalyze(*analyzeLogPath, *analyzeOutputPath)

	case "cleanup":
		_ = cleanupCmd.Parse(os.Args[2:])
		runCleanup(*cleanupDBURL)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("SSF Benchmark Driver")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  driver setup    - Create test data (users, clients, streams, subjects)")
	fmt.Println("  driver emit     - Emit session-revoked events for all users")
	fmt.Println("  driver poll     - Start Long Polling and record received SETs")
	fmt.Println("  driver analyze  - Analyze receive logs")
	fmt.Println("  driver cleanup  - Remove test data")
	fmt.Println()
	fmt.Println("Run 'driver <command> -h' for command-specific help.")
}

func runSetup(dbURL, idpURL string, rps, users int, receiverURL, mode, tokensFile string) {
	ctx := context.Background()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	cfg := driver.SetupConfig{
		RPCount:      rps,
		UserCount:    users,
		ReceiverURL:  receiverURL,
		DeliveryMode: mode,
		IdPURL:       idpURL,
		TokensFile:   tokensFile,
	}

	result, err := driver.SetupTestData(ctx, db, cfg)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	log.Println("Setup complete!")
	log.Printf("  Users:   %d", len(result.UserIDs))
	log.Printf("  Streams: %d", len(result.StreamIDs))
	log.Printf("  Tokens:  %s", tokensFile)
}

func runEmit(dbURL, idpURL string, concurrency int) {
	ctx := context.Background()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Get benchmark user IDs (now using UUID, not username)
	rows, err := db.QueryContext(ctx, `SELECT id FROM users WHERE username LIKE 'bench_user_%' ORDER BY username`)
	if err != nil {
		log.Fatalf("Failed to query users: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var userIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			log.Fatalf("Failed to scan user: %v", err)
		}
		userIDs = append(userIDs, id)
	}

	if len(userIDs) == 0 {
		log.Fatal("No benchmark users found. Run 'driver setup' first.")
	}

	cfg := driver.EmitConfig{
		IdPURL:      idpURL,
		UserIDs:     userIDs,
		Concurrency: concurrency,
	}

	log.Printf("Starting emission for %d users...", len(userIDs))
	startTime := time.Now()

	result, err := driver.EmitEvents(ctx, cfg)
	if err != nil {
		log.Fatalf("Emit failed: %v", err)
	}

	log.Println()
	log.Println("=== Emission Results ===")
	log.Printf("Total Users:    %d", result.TotalUsers)
	log.Printf("Emitted:        %d", result.TotalEmitted)
	log.Printf("Failed:         %d", result.TotalFailed)
	log.Printf("Duration:       %d ms", result.DurationMS)
	log.Printf("Emit Rate:      %.2f events/sec", result.EventsPerSec)
	log.Printf("Elapsed:        %v", time.Since(startTime))
}

func runAnalyze(logPath, outputPath string) {
	result, err := driver.AnalyzeResults(logPath)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	driver.PrintAnalysisResult(result)

	if outputPath != "" {
		// Save to JSON file
		f, err := os.Create(outputPath)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer func() { _ = f.Close() }()

		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			log.Fatalf("Failed to write JSON: %v", err)
		}
		log.Printf("Results saved to: %s", outputPath)
	}
}

func runCleanup(dbURL string) {
	ctx := context.Background()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := driver.CleanupTestData(ctx, db); err != nil {
		log.Fatalf("Cleanup failed: %v", err)
	}

	log.Println("Cleanup complete!")
}

func runPoll(idpURL, tokensFile string, timeout time.Duration, logPath string) {
	ctx := context.Background()

	// Load tokens from file
	streamTokens, err := driver.LoadTokensFromFile(tokensFile)
	if err != nil {
		log.Fatalf("Failed to load tokens: %v", err)
	}

	if len(streamTokens) == 0 {
		log.Fatal("No tokens found. Run 'driver setup -mode poll' first.")
	}

	cfg := driver.PollConfig{
		IdPURL:       idpURL,
		StreamTokens: streamTokens,
		Timeout:      timeout,
		LogPath:      logPath,
	}

	log.Printf("Starting poll benchmark for %d streams...", len(streamTokens))

	result, err := driver.RunPollBenchmark(ctx, cfg)
	if err != nil {
		log.Fatalf("Poll failed: %v", err)
	}

	log.Println()
	log.Println("=== Poll Results ===")
	log.Printf("Total Streams:  %d", result.TotalStreams)
	log.Printf("Total Received: %d", result.TotalReceived)
	log.Printf("Total Polls:    %d", result.TotalPolls)
	log.Printf("Duration:       %d ms", result.DurationMS)
}
