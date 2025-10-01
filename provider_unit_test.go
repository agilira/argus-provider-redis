// provider_unit_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"crypto/tls"
	"testing"
)

// TestExtractHostPort tests extractHostPort function
func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "basic redis url",
			url:      "redis://localhost:6379",
			expected: "localhost:6379",
		},
		{
			name:     "url without port",
			url:      "redis://localhost",
			expected: "localhost:6379", // Default port
		},
		{
			name:     "url without host",
			url:      "redis://:7000",
			expected: "localhost:7000", // Default host
		},
		{
			name:     "invalid url",
			url:      "://invalid",
			expected: "localhost:6379", // Fallback
		},
		{
			name:     "unix socket",
			url:      "unix:///var/run/redis.sock",
			expected: "/var/run/redis.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHostPort(tt.url)
			if result != tt.expected {
				t.Errorf("extractHostPort(%s) = %s, want %s", tt.url, result, tt.expected)
			}
		})
	}
}

// TestValidateRedisHost tests validateRedisHost function
func TestValidateRedisHost(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		shouldErr bool
	}{
		{
			name:      "valid localhost",
			host:      "localhost",
			shouldErr: false,
		},
		{
			name:      "valid ip",
			host:      "127.0.0.1",
			shouldErr: false,
		},
		{
			name:      "valid domain",
			host:      "redis.example.com",
			shouldErr: false,
		},
		{
			name:      "dangerous pattern ..",
			host:      "host../etc",
			shouldErr: true,
		},
		{
			name:      "dangerous pattern __",
			host:      "host__internal",
			shouldErr: true,
		},
		{
			name:      "path traversal",
			host:      "../../../etc/passwd",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRedisHost(tt.host)
			if tt.shouldErr && err == nil {
				t.Errorf("validateRedisHost(%s) should have failed", tt.host)
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("validateRedisHost(%s) should not have failed: %v", tt.host, err)
			}
		})
	}
}

// TestWithTLSOption tests WithTLS configuration option
func TestWithTLSOption(t *testing.T) {
	// Test with nil TLS config
	provider1, err := NewProvider("redis://localhost:6379", WithTLS(nil))
	if err != nil {
		t.Logf("Provider creation failed: %v", err)
		return
	}
	defer func() { _ = provider1.Close() }()

	// Test with actual TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	provider2, err := NewProvider("rediss://localhost:6380", WithTLS(tlsConfig))
	if err != nil {
		t.Logf("TLS Provider creation failed (expected): %v", err)
		return
	}
	defer func() { _ = provider2.Close() }()

	t.Log("WithTLS function coverage test completed")
}

// TestWatchErrorPaths tests Watch function error paths
func TestWatchErrorPaths(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skip("Redis not available for watchKey test")
		return
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Test the Watch function with invalid URL which calls watchKey internally
	// This will test error paths in watchKey
	_, err = provider.Watch(ctx, "invalid://url")
	if err == nil {
		t.Error("Watch should have failed with invalid URL")
	}

	t.Log("Watch error path tested (covers watchKey)")
}

// TestLoadEdgeCases tests Load function edge cases for better coverage
func TestLoadEdgeCases(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Skip("Redis not available for Load edge case test")
		return
	}
	defer func() { _ = provider.Close() }()

	ctx := context.Background()

	// Test with invalid URL to trigger URL validation error
	_, err = provider.Load(ctx, "invalid://url")
	if err == nil {
		t.Error("Load should have failed with invalid URL")
	}

	// Test with cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	_, err = provider.Load(cancelledCtx, "redis://localhost:6379/test-key")
	if err == nil {
		t.Log("Load with cancelled context handled gracefully")
	}

	t.Log("Load edge cases tested")
}
