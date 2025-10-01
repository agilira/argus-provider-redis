package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	redis "github.com/agilira/argus-provider-redis"
)

func main() {
	fmt.Println("Argus Redis Provider Example")
	fmt.Println("============================")

	// Create context for all operations
	ctx := context.Background()

	// Create Redis provider with options
	provider, err := redis.NewProvider("redis://localhost:6379",
		redis.WithPassword(""),            // No password for local Redis
		redis.WithDatabase(0),             // Use database 0
		redis.WithTimeout(10*time.Second), // 10 second timeout
		redis.WithMaxRetries(3),           // 3 retries on failure
		redis.WithPoolSize(10),            // Connection pool of 10
	)
	if err != nil {
		log.Fatalf("Failed to create Redis provider: %v", err)
	}
	// Graceful shutdown for production deployments (following Argus patterns)
	defer func() {
		fmt.Println("\nInitiating graceful shutdown...")
		if err := provider.GracefulShutdown(10 * time.Second); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
			// Fallback to immediate close
			if closeErr := provider.Close(); closeErr != nil {
				log.Printf("Failed to close provider: %v", closeErr)
			}
		} else {
			fmt.Println("Graceful shutdown completed successfully")
		}
	}()

	// Example configuration URL (following Argus pattern: redis://host:port/key)
	configURL := "redis://localhost:6379/app-config"

	// Health check
	fmt.Print("Checking Redis connection... ")
	if err := provider.HealthCheck(ctx, configURL); err != nil {
		fmt.Printf("FAILED: %v\n", err)
		fmt.Println("Make sure Redis is running on localhost:6379")
		return
	}
	fmt.Println("OK")

	// Example 1: Basic Load operation
	fmt.Println("\n1. Basic Configuration Loading")
	fmt.Println("------------------------------")

	// Try loading a configuration key
	config, err := provider.Load(ctx, configURL)
	if err != nil {
		fmt.Printf("Config not found (this is normal for first run): %v\n", err)
	} else {
		fmt.Printf("Loaded config: %v\n", config)
	}

	// Show provider interface compliance
	fmt.Printf("Provider name: %s\n", provider.Name())
	fmt.Printf("Provider scheme: %s\n", provider.Scheme())

	// Example 2: Configuration watching
	fmt.Println("\n2. Configuration Watching")
	fmt.Println("-------------------------")

	// Start watching for changes
	watchURL := "redis://localhost:6379/example-watch-key"
	configChan, err := provider.Watch(ctx, watchURL)
	if err != nil {
		log.Printf("Failed to start watching: %v", err)
	} else {
		fmt.Printf("Started watching: %s\n", watchURL)
		fmt.Println("To test watching, set a value in Redis:")
		fmt.Printf("  redis-cli SET example-watch-key \"Hello, Argus!\"\n")

		// Start a goroutine to handle configuration changes
		go func() {
			for config := range configChan {
				fmt.Printf("Config changed: %v\n", config)
			}
		}()
	}

	// Example 3: Provider statistics
	fmt.Println("\n3. Provider Statistics")
	fmt.Println("----------------------")

	stats := provider.GetStats()
	for key, value := range stats {
		fmt.Printf("  %-20s: %v\n", key, value)
	}

	// Example 4: Security validation demo
	fmt.Println("\n4. Security Validation Demo")
	fmt.Println("---------------------------")
	fmt.Println("Testing security features (these blocks are EXPECTED and demonstrate proper security):")

	dangerousURLs := []string{
		"redis://localhost:6379/../etc/passwd", // Path traversal
		"redis://localhost:6379/FLUSHDB",       // Dangerous command
		"redis://localhost:6379/config__set",   // Double underscore
		"redis://localhost:6379/normal-key",    // This should work
	}

	blockedCount := 0
	for _, testURL := range dangerousURLs {
		// First test validation
		err := provider.Validate(testURL)
		if err != nil {
			blockedCount++
			fmt.Printf("  Security working: '%s' - %v\n", testURL, err)
			continue
		}

		// Then test loading
		_, err = provider.Load(ctx, testURL)
		if err != nil {
			blockedCount++
			fmt.Printf("  Security working: '%s' - %v\n", testURL, err)
		} else {
			fmt.Printf("  Allowed (safe): '%s'\n", testURL)
		}
	}
	fmt.Printf("Security test complete: %d/3 dangerous patterns correctly blocked\n", blockedCount)

	// Example 5: Performance testing
	fmt.Println("\n5. Performance Testing")
	fmt.Println("----------------------")

	start := time.Now()
	operations := 100
	perfURL := "redis://localhost:6379/performance-test-key"

	for i := 0; i < operations; i++ {
		_, _ = provider.Load(ctx, perfURL)
	}

	duration := time.Since(start)
	fmt.Printf("Completed %d operations in %v\n", operations, duration)
	fmt.Printf("Average: %v per operation\n", duration/time.Duration(operations))

	// Setup graceful shutdown handling (production pattern)
	fmt.Println("\n6. Monitoring Mode")
	fmt.Println("------------------")
	fmt.Println("Monitoring for 30 seconds... Change values in Redis to see live updates!")
	fmt.Println("Press Ctrl+C for graceful shutdown demonstration")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	timeout := time.After(30 * time.Second)

	for {
		select {
		case <-ticker.C:
			// Show updated stats every 5 seconds
			stats := provider.GetStats()
			fmt.Printf("Requests: %v, Errors: %v (security blocks), Watches: %v\n",
				stats["total_requests"],
				stats["total_errors"],
				stats["active_watches"])

		case sig := <-sigChan:
			fmt.Printf("\nReceived signal: %v\n", sig)
			fmt.Println("Demonstrating graceful shutdown...")
			ticker.Stop()
			return

		case <-timeout:
			fmt.Println("\nExample completed!")
			ticker.Stop()
			return
		}
	}
}
