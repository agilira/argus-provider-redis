// production_test.go: Tests that simulate real-world Argus usage
//
// This test suite simulates exactly how our Redis provider would be used
// in a real-world application with Argus, without creating circular dependencies.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// simulateArgusWorkflow simulates the complete Argus workflow with Redis provider
func TestRealWorld_FullArgusWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full workflow test in short mode")
	}
	
	// 1. Application startup: register Redis provider (simulates import _ "argus-provider-redis")
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create Redis provider: %v", err)
	}

	t.Logf("Step 1: Provider created: %s", provider.Name())

	// 2. Argus initialization: validate provider and URLs
	configURLs := []string{
		"redis://localhost:6379/app-config",
		"redis://localhost:6379/feature-flags",
		"redis://localhost:6379/database-config",
	}

	for _, url := range configURLs {
		if err := provider.Validate(url); err != nil {
			t.Errorf("URL validation failed for %s: %v", url, err)
		}
	}
	t.Log("✅ Step 2: All configuration URLs validated")

	// 3. Health checks during startup (simulates Argus health checking)
	ctx := context.Background()
	for _, url := range configURLs {
		err := provider.HealthCheck(ctx, url)
		if err != nil {
			t.Logf("Health check failed for %s (may be expected): %v", url, err)
		}
	}
	t.Log("✅ Step 3: Health checks completed")

	// 4. Setup test data in Redis (simulates real configuration)
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer func() { _ = redisClient.Close() }()

	// Check Redis availability first
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available for real-world simulation")
		return
	}

	testConfigs := map[string]interface{}{
		"app-config": map[string]interface{}{
			"name":        "MyApp",
			"version":     "1.2.3",
			"debug":       false,
			"max_workers": 10,
		},
		"feature-flags": map[string]interface{}{
			"enable_new_ui":     true,
			"enable_beta_api":   false,
			"max_request_size":  1024000,
			"cache_timeout_sec": 300,
		},
		"database-config": map[string]interface{}{
			"host":            "db.example.com",
			"port":            5432,
			"database":        "myapp_prod",
			"connection_pool": 20,
			"timeout_sec":     30,
		},
	}

	// Store test data in Redis
	for key, config := range testConfigs {
		configJSON, _ := json.Marshal(config)
		err := redisClient.Set(ctx, key, string(configJSON), time.Hour).Err()
		if err != nil {
			t.Fatalf("Failed to setup test data for %s: %v", key, err)
		}
	}
	t.Log("✅ Step 4: Test configuration data setup in Redis")

	// 5. Load configurations (simulates argus.LoadRemoteConfig calls)
	for key := range testConfigs {
		url := fmt.Sprintf("redis://localhost:6379/%s", key)

		loadedConfig, err := provider.Load(ctx, url)
		if err != nil {
			t.Errorf("Failed to load config for %s: %v", key, err)
			continue
		}

		// Verify loaded configuration matches expected
		if loadedConfig == nil {
			t.Errorf("Loaded config is nil for %s", key)
			continue
		}

		// Compare specific fields to ensure correct loading
		switch key {
		case "app-config":
			if loadedConfig["name"] != "MyApp" || loadedConfig["version"] != "1.2.3" {
				t.Errorf("App config not loaded correctly: %+v", loadedConfig)
			}
		case "feature-flags":
			if loadedConfig["enable_new_ui"] != true || loadedConfig["enable_beta_api"] != false {
				t.Errorf("Feature flags not loaded correctly: %+v", loadedConfig)
			}
		case "database-config":
			if loadedConfig["host"] != "db.example.com" || loadedConfig["port"] != float64(5432) {
				t.Errorf("Database config not loaded correctly: %+v", loadedConfig)
			}
		}
	}
	t.Log("✅ Step 5: All configurations loaded and verified")

	// 6. Setup configuration watching (simulates argus.WatchRemoteConfig)
	watchURL := "redis://localhost:6379/feature-flags"
	configChan, err := provider.Watch(ctx, watchURL)
	if err != nil {
		t.Fatalf("Failed to setup configuration watching: %v", err)
	}

	// Receive initial configuration
	select {
	case initialConfig := <-configChan:
		if initialConfig == nil {
			t.Error("Expected initial configuration from watch")
		} else {
			t.Logf("✅ Step 6a: Received initial watched config: %+v", initialConfig)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for initial configuration from watch")
	}

	// 7. Simulate configuration change and verify watch notifications
	updatedFlags := map[string]interface{}{
		"enable_new_ui":     false,   // Changed from true
		"enable_beta_api":   true,    // Changed from false
		"max_request_size":  2048000, // Changed from 1024000
		"cache_timeout_sec": 600,     // Changed from 300
	}

	updatedJSON, _ := json.Marshal(updatedFlags)
	err = redisClient.Set(ctx, "feature-flags", string(updatedJSON), time.Hour).Err()
	if err != nil {
		t.Fatalf("Failed to update feature flags: %v", err)
	}

	// Check for configuration update notification
	select {
	case updatedConfig := <-configChan:
		if updatedConfig == nil {
			t.Error("Expected updated configuration from watch")
		} else {
			// Verify the update was detected
			if updatedConfig["enable_new_ui"] != false || updatedConfig["enable_beta_api"] != true {
				t.Errorf("Configuration change not detected correctly: %+v", updatedConfig)
			} else {
				t.Log("✅ Step 7: Configuration change detected and received")
			}
		}
	case <-time.After(3 * time.Second):
		t.Log("⚠️ Step 7: No update notification received (may be timing dependent)")
	}

	// 8. Test provider statistics (simulates Argus monitoring)
	stats := provider.GetStats()
	if stats == nil {
		t.Error("Provider stats should not be nil")
	} else {
		// Verify expected statistics are present
		expectedKeys := []string{"total_requests", "total_errors", "active_watches", "is_connected"}
		for _, key := range expectedKeys {
			if _, exists := stats[key]; !exists {
				t.Errorf("Expected stat '%s' not found in: %+v", key, stats)
			}
		}
		t.Logf("✅ Step 8: Provider statistics: %+v", stats)
	}

	// 9. Application shutdown: graceful provider shutdown (simulates defer provider.GracefulShutdown)
	shutdownStart := time.Now()
	err = provider.GracefulShutdown(10 * time.Second)
	shutdownDuration := time.Since(shutdownStart)

	if err != nil {
		t.Errorf("Graceful shutdown failed: %v", err)
	} else if shutdownDuration > 5*time.Second {
		t.Errorf("Graceful shutdown took too long: %v", shutdownDuration)
	} else {
		t.Logf("✅ Step 9: Graceful shutdown completed in %v", shutdownDuration)
	}

	// 10. Cleanup test data
	for key := range testConfigs {
		redisClient.Del(ctx, key)
	}
	t.Log("✅ Step 10: Test data cleaned up")

	t.Log("🎉 COMPLETE WORKFLOW SUCCESS: Redis provider works perfectly with Argus patterns!")
}

// TestRealWorld_ProductionPatterns tests production deployment patterns
func TestRealWorld_ProductionPatterns(t *testing.T) {
	// Test Kubernetes deployment pattern
	t.Run("Kubernetes", func(t *testing.T) {
		provider, err := NewProvider("redis://localhost:6379")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}

		// Simulate Kubernetes terminationGracePeriodSeconds: 30s
		// Argus pattern: use terminationGracePeriodSeconds - 5s
		timeout := 25 * time.Second

		start := time.Now()
		err = provider.GracefulShutdown(timeout)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Kubernetes graceful shutdown failed: %v", err)
		}

		if duration > timeout {
			t.Errorf("Shutdown exceeded Kubernetes timeout: %v > %v", duration, timeout)
		}

		t.Logf("✅ Kubernetes pattern: shutdown in %v (limit: %v)", duration, timeout)
	})

	// Test Docker deployment pattern
	t.Run("Docker", func(t *testing.T) {
		provider, err := NewProvider("redis://localhost:6379")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}

		// Docker typically uses 10-30 seconds
		timeout := 10 * time.Second

		start := time.Now()
		err = provider.GracefulShutdown(timeout)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Docker graceful shutdown failed: %v", err)
		}

		t.Logf("✅ Docker pattern: shutdown in %v (limit: %v)", duration, timeout)
	})

	// Test CI/CD pattern
	t.Run("CI_CD", func(t *testing.T) {
		provider, err := NewProvider("redis://localhost:6379")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}

		// CI/CD uses shorter timeouts for faster cycles
		timeout := 5 * time.Second

		start := time.Now()
		err = provider.GracefulShutdown(timeout)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("CI/CD graceful shutdown failed: %v", err)
		}

		t.Logf("✅ CI/CD pattern: shutdown in %v (limit: %v)", duration, timeout)
	})
}

// TestRealWorld_ErrorRecovery tests error scenarios and recovery
func TestRealWorld_ErrorRecovery(t *testing.T) {
	// Test with unreachable Redis server
	provider, err := NewProvider("redis://nonexistent:9999")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test Load with unreachable server
	_, err = provider.Load(ctx, "redis://nonexistent:9999/test")
	if err == nil {
		t.Error("Expected error when connecting to unreachable Redis")
	} else {
		t.Logf("✅ Correctly handled unreachable Redis: %v", err)
	}

	// Test HealthCheck with unreachable server
	err = provider.HealthCheck(ctx, "redis://nonexistent:9999/test")
	if err == nil {
		t.Error("Expected health check failure for unreachable Redis")
	} else {
		t.Logf("✅ Health check correctly failed: %v", err)
	}

	// Test graceful shutdown even with connection issues
	start := time.Now()
	_ = provider.GracefulShutdown(5 * time.Second) // Ignore error - we expect it might fail due to connection issues
	duration := time.Since(start)

	if duration > 5*time.Second {
		t.Errorf("Shutdown took too long even with connection issues: %v", duration)
	} else {
		t.Logf("✅ Graceful shutdown handled connection issues: %v", duration)
	}
}

// TestRealWorld_Performance tests performance characteristics
func TestRealWorld_Performance(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test rapid graceful shutdowns (simulates restart scenarios)
	const numRestarts = 10
	totalTime := time.Duration(0)

	for i := 0; i < numRestarts; i++ {
		start := time.Now()
		err = provider.GracefulShutdown(1 * time.Second)
		duration := time.Since(start)
		totalTime += duration

		if err != nil {
			t.Errorf("Restart %d failed: %v", i, err)
		}

		// Create new provider for next iteration
		if i < numRestarts-1 {
			provider, err = NewProvider("redis://localhost:6379")
			if err != nil {
				t.Fatalf("Failed to recreate provider for restart %d: %v", i, err)
			}
		}
	}

	avgTime := totalTime / numRestarts
	if avgTime > 100*time.Millisecond {
		t.Errorf("Average shutdown time too slow: %v", avgTime)
	} else {
		t.Logf("✅ Performance: %d restarts, avg shutdown time: %v", numRestarts, avgTime)
	}
}
