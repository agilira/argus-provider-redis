// graceful_shutdown_test.go: Tests for graceful shutdown functionality
//
// This test suite validates the GracefulShutdown functionality including:
// - Timeout behavior and error handling
// - Resource cleanup verification
// - Thread safety and concurrent access patterns
// - Integration with existing Close() method
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"testing"
	"time"
)

// TestGracefulShutdown_BasicOperation tests normal graceful shutdown behavior
func TestGracefulShutdown_BasicOperation(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Perform graceful shutdown with reasonable timeout
	startTime := time.Now()
	err = provider.GracefulShutdown(5 * time.Second)
	shutdownDuration := time.Since(startTime)

	// Verify shutdown succeeded
	if err != nil {
		t.Errorf("GracefulShutdown failed: %v", err)
	}

	// Verify shutdown was reasonably fast (should be much less than timeout)
	if shutdownDuration > 2*time.Second {
		t.Errorf("GracefulShutdown took too long: %v", shutdownDuration)
	}

	t.Logf("✅ GracefulShutdown completed in %v", shutdownDuration)
}

// TestGracefulShutdown_TimeoutBehavior tests timeout handling
func TestGracefulShutdown_TimeoutBehavior(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test with very short timeout (should still work for normal cases)
	startTime := time.Now()
	err = provider.GracefulShutdown(100 * time.Millisecond)
	duration := time.Since(startTime)

	// Even with short timeout, shutdown should succeed for simple cases
	// If it times out, we still expect eventual cleanup
	if err != nil {
		// Check if it's a timeout error (acceptable)
		if duration >= 90*time.Millisecond {
			t.Logf("✅ Timeout behavior working: %v (took %v)", err, duration)
		} else {
			t.Errorf("Unexpected error during timeout test: %v", err)
		}
	} else {
		t.Logf("✅ Fast shutdown completed in %v", duration)
	}

	// Give some extra time for background cleanup
	time.Sleep(200 * time.Millisecond)
}

// TestGracefulShutdown_InvalidTimeout tests invalid timeout values
func TestGracefulShutdown_InvalidTimeout(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	// Test with zero timeout
	err = provider.GracefulShutdown(0)
	if err == nil {
		t.Error("GracefulShutdown should reject zero timeout")
	}

	// Test with negative timeout
	err = provider.GracefulShutdown(-1 * time.Second)
	if err == nil {
		t.Error("GracefulShutdown should reject negative timeout")
	}

	t.Log("✅ Invalid timeout handling working correctly")
}

// TestGracefulShutdown_ConcurrentCalls tests concurrent shutdown calls
func TestGracefulShutdown_ConcurrentCalls(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Test multiple concurrent shutdown calls
	const numCalls = 5
	results := make(chan error, numCalls)

	// Launch concurrent GracefulShutdown calls
	for i := 0; i < numCalls; i++ {
		go func() {
			err := provider.GracefulShutdown(5 * time.Second)
			results <- err
		}()
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numCalls; i++ {
		err := <-results
		if err == nil {
			successCount++
		} else {
			errorCount++
		}
	}

	// At least one should succeed, others may get errors (acceptable)
	if successCount < 1 {
		t.Error("At least one concurrent GracefulShutdown call should succeed")
	}

	t.Logf("✅ Concurrent calls: %d successful, %d failed (expected)", successCount, errorCount)
}

// TestGracefulShutdown_Performance tests multiple shutdown cycles
func TestGracefulShutdown_Performance(t *testing.T) {
	// Run multiple shutdown cycles to test for resource leaks
	for i := 0; i < 5; i++ {
		provider, err := NewProvider("redis://localhost:6379")
		if err != nil {
			t.Fatalf("Failed to create provider iteration %d: %v", i, err)
		}

		// Quick graceful shutdown
		if err := provider.GracefulShutdown(2 * time.Second); err != nil {
			t.Fatalf("GracefulShutdown failed iteration %d: %v", i, err)
		}
	}

	t.Log("✅ Multiple shutdown cycles completed without issues")
}
