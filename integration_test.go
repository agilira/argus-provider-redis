// integration_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"testing"
	"time"
)

// RemoteConfigProvider interface for testing (copied from argus/remote_config.go)
type RemoteConfigProvider interface {
	Name() string
	Scheme() string
	Load(ctx context.Context, configURL string) (map[string]interface{}, error)
	Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error)
	Validate(configURL string) error
	HealthCheck(ctx context.Context, configURL string) error
}

// TestRealRedisConnection tests actual Redis connectivity
func TestRealRedisConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real Redis connection test in short mode")
	}
	
	// Skip if no Redis available
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	ctx := context.Background()

	// Test health check
	if err := provider.HealthCheck(ctx, "redis://localhost:6379/app-config"); err != nil {
		t.Skipf("Redis health check failed: %v", err)
	}

	t.Log("✅ Redis connection successful")

	// Test basic load operation
	config, err := provider.Load(ctx, "redis://localhost:6379/app-config")
	if err != nil {
		t.Logf("Config load failed (expected if no data): %v", err)
	} else {
		t.Logf("✅ Loaded config: %v", config)
	}

	// Test interface compliance
	var _ RemoteConfigProvider = provider
	t.Log("✅ Provider implements RemoteConfigProvider interface")

	// Test stats
	stats := provider.GetStats()
	t.Logf("✅ Provider stats: %+v", stats)
}

// TestRealRedisWatch tests watching functionality with real Redis
func TestRealRedisWatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real Redis watch test in short mode")
	}
	
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	ctx := context.Background()
	watchURL := "redis://localhost:6379/test-watch-" + time.Now().Format("150405")

	if err := provider.HealthCheck(ctx, watchURL); err != nil {
		t.Skipf("Redis health check failed: %v", err)
	}

	// Test watch functionality
	configChan, err := provider.Watch(ctx, watchURL)
	if err != nil {
		t.Fatalf("Failed to start watching: %v", err)
	}

	t.Log("✅ Watch started successfully")

	// Give some time for watch to initialize and receive initial config
	select {
	case config := <-configChan:
		t.Logf("✅ Received initial config: %v", config)
	case <-time.After(2 * time.Second):
		t.Log("No initial config received (expected for non-existent key)")
	}

	stats := provider.GetStats()
	activeWatches := stats["active_watches"]
	t.Logf("✅ Active watches: %v", activeWatches)
}

// BenchmarkRealRedisLoad benchmarks load performance with real Redis
func BenchmarkRealRedisLoad(b *testing.B) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		b.Skipf("Redis not available: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			b.Errorf("Failed to close provider: %v", err)
		}
	}()

	ctx := context.Background()
	testURL := "redis://localhost:6379/benchmark-key"

	if err := provider.HealthCheck(ctx, testURL); err != nil {
		b.Skipf("Redis health check failed: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = provider.Load(ctx, testURL)
		}
	})
}
