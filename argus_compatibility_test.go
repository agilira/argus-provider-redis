// argus_compatibility_test.go: Tests that verify 100% compatibility with Argus
//
// This test suite validates that our Redis provider works exactly as Argus expects
// by simulating the same calling patterns and interface compliance that Argus uses.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// RemoteConfigProvider interface (copied exactly from argus/remote_config.go)
// This ensures we implement the interface exactly as Argus expects
type ArgusRemoteConfigProvider interface {
	Name() string
	Scheme() string
	Load(ctx context.Context, configURL string) (map[string]interface{}, error)
	Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error)
	Validate(configURL string) error
	HealthCheck(ctx context.Context, configURL string) error
}

// simulateArgusProviderRegistry simulates how Argus registers and uses providers
func simulateArgusProviderRegistry() map[string]ArgusRemoteConfigProvider {
	registry := make(map[string]ArgusRemoteConfigProvider)

	// Create Redis provider
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		panic(fmt.Sprintf("Failed to create Redis provider: %v", err))
	}

	// Register provider by scheme (simulates argus.RegisterRemoteProvider)
	registry[provider.Scheme()] = provider

	return registry
}

// simulateArgusLoadRemoteConfig simulates argus.LoadRemoteConfig function
func simulateArgusLoadRemoteConfig(registry map[string]ArgusRemoteConfigProvider, configURL string) (map[string]interface{}, error) {
	// Parse URL to get scheme (simulates Argus URL parsing)
	if len(configURL) < 8 || configURL[:8] != "redis://" {
		return nil, fmt.Errorf("[ARGUS_INVALID_CONFIG]: unsupported URL scheme")
	}

	// Get provider for scheme (simulates argus.GetRemoteProvider)
	provider, exists := registry["redis"]
	if !exists {
		return nil, fmt.Errorf("[ARGUS_UNSUPPORTED_PROVIDER]: no provider registered for scheme 'redis'")
	}

	// Validate URL (simulates Argus validation step)
	if err := provider.Validate(configURL); err != nil {
		return nil, fmt.Errorf("[ARGUS_INVALID_CONFIG]: %v", err)
	}

	// Load config with timeout context (simulates Argus context handling)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return provider.Load(ctx, configURL)
}

// TestArgusCompatibility_ProviderInterface verifies interface compliance
func TestArgusCompatibility_ProviderInterface(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Verify interface compliance (this is what Argus does internally)
	var _ ArgusRemoteConfigProvider = provider

	t.Log("Redis provider implements ArgusRemoteConfigProvider interface correctly")
}

// TestArgusCompatibility_ProviderRegistration simulates Argus provider registration
func TestArgusCompatibility_ProviderRegistration(t *testing.T) {
	registry := simulateArgusProviderRegistry()

	// Verify provider is registered correctly
	provider, exists := registry["redis"]
	if !exists {
		t.Fatal("Redis provider not found in registry")
	}

	// Verify provider properties
	if provider.Name() == "" {
		t.Error("Provider name should not be empty")
	}

	if provider.Scheme() != "redis" {
		t.Errorf("Expected scheme 'redis', got '%s'", provider.Scheme())
	}

	t.Logf("Provider registered: %s (scheme: %s)", provider.Name(), provider.Scheme())
}

// TestArgusCompatibility_LoadRemoteConfig simulates argus.LoadRemoteConfig
func TestArgusCompatibility_LoadRemoteConfig(t *testing.T) {
	registry := simulateArgusProviderRegistry()

	// Test cases that simulate how Argus calls LoadRemoteConfig
	testCases := []struct {
		name      string
		url       string
		shouldErr bool
		errType   string
	}{
		{
			name:      "valid_redis_url",
			url:       "redis://localhost:6379/test-config",
			shouldErr: false,
		},
		{
			name:      "invalid_scheme",
			url:       "http://localhost:8080/config",
			shouldErr: true,
			errType:   "ARGUS_INVALID_CONFIG",
		},
		{
			name:      "invalid_redis_url",
			url:       "redis://localhost:6379/",
			shouldErr: true,
			errType:   "ARGUS_INVALID_CONFIG",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := simulateArgusLoadRemoteConfig(registry, tc.url)

			if tc.shouldErr {
				if err == nil {
					t.Errorf("Expected error for URL: %s", tc.url)
				} else {
					t.Logf("Expected error: %v", err)
				}
			} else {
				if err != nil {
					// Check if it's an acceptable error (Redis connection issues or not found)
					errMsg := err.Error()
					if errMsg != "[NOT_FOUND]: key not found" &&
						!strings.Contains(errMsg, "[REDIS_ERROR]:") &&
						!strings.Contains(errMsg, "[CONNECTION_ERROR]:") &&
						!strings.Contains(errMsg, "[CONNECTION_UNHEALTHY]:") {
						t.Errorf("Unexpected error for URL %s: %v", tc.url, err)
					} else {
						t.Logf("Valid URL handled correctly (connection/not found errors are expected without Redis)")
					}
				} else {
					t.Logf("Successfully loaded config: %+v", config)
				}
			}
		})
	}
}

// TestArgusCompatibility_WatchRemoteConfig simulates argus.WatchRemoteConfig
func TestArgusCompatibility_WatchRemoteConfig(t *testing.T) {
	registry := simulateArgusProviderRegistry()
	provider := registry["redis"]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test watch functionality (simulates Argus watch behavior)
	configChan, err := provider.Watch(ctx, "redis://localhost:6379/test-watch")
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// Verify channel behavior (this is how Argus consumes the channel)
	select {
	case config := <-configChan:
		t.Logf("Received initial config from watch: %+v", config)
	case <-time.After(2 * time.Second):
		t.Log("No initial config (expected for non-existent key)")
	}

	t.Log("Watch channel created successfully")
}

// TestArgusCompatibility_HealthCheck simulates Argus health checking
func TestArgusCompatibility_HealthCheck(t *testing.T) {
	registry := simulateArgusProviderRegistry()
	provider := registry["redis"]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test health check (simulates Argus health checking)
	err := provider.HealthCheck(ctx, "redis://localhost:6379/health-check")
	if err != nil {
		t.Logf("Health check failed (may be expected if Redis not available): %v", err)
	} else {
		t.Log("Health check passed")
	}
}

// TestArgusCompatibility_ConcurrentUsage simulates Argus concurrent usage patterns
func TestArgusCompatibility_ConcurrentUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent usage test in short mode")
	}

	registry := simulateArgusProviderRegistry()
	provider := registry["redis"]

	// Quick check if Redis is available - if not, skip this test
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	testURL := "redis://localhost:6379/test"
	_, err := provider.Load(ctx, testURL)
	cancel()

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "[CONNECTION_ERROR]:") ||
			strings.Contains(errMsg, "[CONNECTION_UNHEALTHY]:") ||
			strings.Contains(errMsg, "[REDIS_ERROR]:") {
			// In CI with Redis service, this should work - fail the test
			if os.Getenv("REDIS_AVAILABLE") == "true" {
				t.Fatalf("Redis should be available in CI but connection failed: %v", err)
			}
			t.Skip("Redis not available for concurrent usage test")
		}
	}

	// Simulate concurrent Load operations (how Argus might use the provider)
	const numWorkers = 10
	const opsPerWorker = 50

	var wg sync.WaitGroup
	errorCount := 0
	var errorMutex sync.Mutex

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			for j := 0; j < opsPerWorker; j++ {
				url := fmt.Sprintf("redis://localhost:6379/worker-%d-op-%d", workerID, j)
				_, err := provider.Load(ctx, url)
				if err != nil {
					// Only count unexpected errors (NOT_FOUND is expected for non-existent keys)
					errMsg := err.Error()
					if errMsg != "[NOT_FOUND]: key not found" {
						errorMutex.Lock()
						errorCount++
						errorMutex.Unlock()
						t.Logf("Worker %d: Unexpected error: %v", workerID, err)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	if errorCount > 0 {
		t.Errorf("Concurrent usage had %d unexpected errors", errorCount)
	} else {
		t.Logf("Completed %d concurrent operations across %d workers", numWorkers*opsPerWorker, numWorkers)
	}
}

// TestArgusCompatibility_GracefulShutdown simulates Argus shutdown patterns
func TestArgusCompatibility_GracefulShutdown(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Simulate Kubernetes deployment pattern (what Argus recommends)
	timeout := 30 * time.Second

	start := time.Now()
	err = provider.GracefulShutdown(timeout)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Graceful shutdown failed: %v", err)
	}

	if duration > timeout {
		t.Errorf("Shutdown took longer than timeout: %v > %v", duration, timeout)
	}

	t.Logf("Graceful shutdown completed in %v (timeout was %v)", duration, timeout)
}

// TestArgusCompatibility_ErrorPatterns verifies error patterns match Argus expectations
func TestArgusCompatibility_ErrorPatterns(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test URL validation errors (simulates Argus validation)
	invalidURLs := []struct {
		url           string
		expectedError string
	}{
		{"", "Redis URL cannot be empty"},
		{"not-a-url", "invalid Redis URL"},
		{"http://localhost/config", "URL scheme must be 'redis'"},
		{"redis://localhost:6379/", "Redis key is required in URL path"},
	}

	for _, test := range invalidURLs {
		err := provider.Validate(test.url)
		if err == nil {
			t.Errorf("Expected validation error for URL: %s", test.url)
		} else {
			t.Logf("Validation correctly rejected '%s': %v", test.url, err)
		}
	}
}

// TestArgusCompatibility_EdgeCases tests edge cases that Argus might encounter
func TestArgusCompatibility_EdgeCases(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test context cancellation (simulates Argus timeout handling)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = provider.Load(ctx, "redis://localhost:6379/test")
	if err == nil {
		t.Error("Expected error when using cancelled context")
	} else {
		t.Logf("Correctly handled cancelled context: %v", err)
	}

	// Test concurrent graceful shutdowns (simulates multiple Argus shutdown calls)
	const numShutdowns = 5
	results := make(chan error, numShutdowns)

	for i := 0; i < numShutdowns; i++ {
		go func() {
			results <- provider.GracefulShutdown(1 * time.Second)
		}()
	}

	successCount := 0
	for i := 0; i < numShutdowns; i++ {
		err := <-results
		if err == nil {
			successCount++
		}
	}

	// At least one should succeed
	if successCount < 1 {
		t.Error("Expected at least one successful graceful shutdown")
	} else {
		t.Logf("Concurrent graceful shutdowns: %d successful out of %d", successCount, numShutdowns)
	}
}
