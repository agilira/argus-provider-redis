package redis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestArgusIntegration simulates how Argus would use the Redis provider
func TestArgusIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	// This test simulates the full Argus integration workflow
	ctx := context.Background()

	// Step 1: Create provider (this would be done by Argus registry)
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	// Step 2: Verify provider implements the interface correctly
	var argusProvider RemoteConfigProvider = provider

	// Test Name and Scheme methods
	name := argusProvider.Name()
	scheme := argusProvider.Scheme()
	t.Logf("✅ Provider: %s (scheme: %s)", name, scheme)

	// Step 3: Test URL validation (this is what Argus would call first)
	testURLs := []struct {
		url   string
		valid bool
	}{
		{"redis://localhost:6379/app-config", true},
		{"redis://localhost:6379/database/settings", true},
		{"", false},
		{"http://invalid", false},
		{"redis://localhost:6379/", false}, // empty key
	}

	for _, test := range testURLs {
		err := argusProvider.Validate(test.url)
		if test.valid && err != nil {
			t.Errorf("Expected valid URL '%s' but got error: %v", test.url, err)
		}
		if !test.valid && err == nil {
			t.Errorf("Expected invalid URL '%s' but validation passed", test.url)
		}
	}
	t.Log("✅ URL validation working correctly")

	// Step 4: Test health check (Argus startup validation)
	testURL := "redis://localhost:6379/app-config"
	if err := argusProvider.HealthCheck(ctx, testURL); err != nil {
		// In CI with Redis service, this should work - fail the test
		if os.Getenv("REDIS_AVAILABLE") == "true" {
			t.Fatalf("Redis should be available in CI but health check failed: %v", err)
		}
		t.Skipf("Health check failed: %v", err)
	}
	t.Log("✅ Health check passed")

	// Step 5: Test configuration loading (main Argus functionality)
	config, err := argusProvider.Load(ctx, testURL)
	if err != nil {
		// This is expected if the key doesn't exist
		t.Logf("Config load failed (expected): %v", err)
	} else {
		t.Logf("✅ Loaded config: %v", config)

		// Verify it's a proper map[string]interface{}
		if config == nil {
			t.Error("Config should not be nil")
		}
		if len(config) == 0 {
			t.Log("Config is empty (this is ok)")
		}
	}

	// Step 6: Test watching (advanced Argus functionality)
	watchURL := "redis://localhost:6379/watch-test"
	configChan, err := argusProvider.Watch(ctx, watchURL)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	t.Log("✅ Watch started successfully")

	// Test receiving initial config (if any)
	select {
	case config := <-configChan:
		t.Logf("✅ Received initial config from watch: %v", config)
	case <-time.After(1 * time.Second):
		t.Log("No initial config (expected for non-existent key)")
	}

	// Step 7: Test provider stats (for monitoring)
	stats := provider.GetStats()
	expectedKeys := []string{"total_requests", "active_watches", "is_connected"}
	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Missing expected stat key: %s", key)
		}
	}
	t.Logf("✅ Provider stats available: %d metrics", len(stats))

	t.Log("✅ Complete Argus integration simulation successful!")
}

// TestArgusProviderRegistration simulates how the provider would be registered with Argus
func TestArgusProviderRegistration(t *testing.T) {
	// This simulates the Argus provider registry
	registry := make(map[string]RemoteConfigProvider)

	// Create and register provider
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	// Register by scheme (this is what Argus does internally)
	scheme := provider.Scheme()
	registry[scheme] = provider

	t.Logf("✅ Registered provider for scheme: %s", scheme)

	// Simulate Argus looking up provider by URL
	testURL := "redis://localhost:6379/my-config"

	// Extract scheme (this is what Argus does)
	if len(testURL) > 0 {
		schemeEnd := 0
		for i, c := range testURL {
			if c == ':' {
				schemeEnd = i
				break
			}
		}

		if schemeEnd > 0 {
			urlScheme := testURL[:schemeEnd]

			// Look up provider (this is what Argus does)
			if foundProvider, exists := registry[urlScheme]; exists {
				t.Logf("✅ Found provider for URL: %s", testURL)

				// Verify it's the same provider
				if foundProvider.Name() != provider.Name() {
					t.Error("Registry returned wrong provider")
				}
			} else {
				t.Errorf("No provider found for scheme: %s", urlScheme)
			}
		}
	}

	t.Log("✅ Provider registration and lookup successful!")
}

// TestConcurrentUsage tests the provider under concurrent load (like Argus would use it)
func TestConcurrentUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent usage test in short mode")
	}

	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	ctx := context.Background()
	testURL := "redis://localhost:6379/concurrent-test"

	// Check if Redis is actually available
	if err := provider.HealthCheck(ctx, testURL); err != nil {
		provider.Close()
		// In CI with Redis service, this should work - fail the test
		if os.Getenv("REDIS_AVAILABLE") == "true" {
			t.Fatalf("Redis should be available in CI but health check failed: %v", err)
		}
		t.Skipf("Redis not available for concurrent testing: %v", err)
	}

	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	// Simulate concurrent requests (like multiple Argus operations)
	concurrency := 10
	requests := 50

	errChan := make(chan error, concurrency*requests)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			for j := 0; j < requests; j++ {
				// Health check - should pass since we verified Redis is available
				if err := provider.HealthCheck(ctx, testURL); err != nil {
					errChan <- fmt.Errorf("worker %d health check %d failed: %v", workerID, j, err)
					return
				}

				// Load config (only if health check passed or with expected Redis errors)
				_, err := provider.Load(ctx, testURL)
				if err != nil {
					// Expected errors when Redis is not available or key doesn't exist
					errMsg := err.Error()
					if errMsg != "[NOT_FOUND]: key not found" &&
						!strings.Contains(errMsg, "[REDIS_ERROR]:") &&
						!strings.Contains(errMsg, "[CONNECTION_ERROR]:") &&
						!strings.Contains(errMsg, "[CONNECTION_UNHEALTHY]:") {
						errChan <- fmt.Errorf("worker %d load %d failed: %v", workerID, j, err)
						return
					}
				}
			}
			errChan <- nil
		}(i)
	}

	// Wait for all workers
	for i := 0; i < concurrency; i++ {
		if err := <-errChan; err != nil {
			t.Error(err)
		}
	}

	// Check final stats
	stats := provider.GetStats()
	totalRequests := stats["total_requests"]
	t.Logf("✅ Completed %v requests across %d workers", totalRequests, concurrency)
}
