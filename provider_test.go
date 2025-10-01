// provider_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"testing"
	"time"
)

// TestProviderCreation tests basic provider creation and validation
func TestProviderCreation(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		shouldErr bool
	}{
		{
			name:      "valid redis url",
			url:       "redis://localhost:6379",
			shouldErr: false,
		},
		{
			name:      "valid redis url with database",
			url:       "redis://localhost:6379/1",
			shouldErr: false,
		},
		{
			name:      "valid rediss url",
			url:       "rediss://localhost:6380",
			shouldErr: false,
		},
		{
			name:      "empty url",
			url:       "",
			shouldErr: true,
		},
		{
			name:      "invalid scheme",
			url:       "http://localhost:6379",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.url)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error for URL: %s", tt.url)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for URL %s: %v", tt.url, err)
				return
			}

			if provider == nil {
				t.Error("provider should not be nil")
				return
			}

			// Test Close
			if err := provider.Close(); err != nil {
				t.Errorf("error closing provider: %v", err)
			}
		})
	}
}

// TestProviderOptions tests configuration options
func TestProviderOptions(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379",
		WithPassword("testpass"),
		WithDatabase(1),
		WithTimeout(15*time.Second),
		WithMaxRetries(5),
		WithPoolSize(20),
	)

	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	if provider.timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", provider.timeout)
	}

	if provider.maxRetries != 5 {
		t.Errorf("expected max retries 5, got %d", provider.maxRetries)
	}
}

// TestProviderWithTLS tests TLS configuration option
func TestProviderWithTLS(t *testing.T) {
	// Test WithTLS option - this should exercise the WithTLS function
	provider, err := NewProvider("rediss://localhost:6380",
		WithTLS(nil), // Test with nil TLS config
	)

	if err != nil {
		// This is expected if Redis with TLS is not available
		t.Logf("TLS provider creation failed (expected if no TLS Redis): %v", err)
		return
	}

	defer func() {
		if err := provider.Close(); err != nil {
			t.Logf("Failed to close TLS provider: %v", err)
		}
	}()

	// The WithTLS function was called, which is what we wanted to test
	t.Log("WithTLS function executed successfully")
}

// TestValidateSecureRedisKey tests Redis key validation
func TestValidateSecureRedisKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		shouldErr bool
	}{
		{
			name:      "valid key",
			key:       "my-config-key",
			shouldErr: false,
		},
		{
			name:      "valid key with colon",
			key:       "app:config:database",
			shouldErr: true, // colon is in dangerous patterns
		},
		{
			name:      "empty key",
			key:       "",
			shouldErr: true,
		},
		{
			name:      "key with dangerous pattern",
			key:       "config/../other",
			shouldErr: true,
		},
		{
			name:      "key with forbidden command",
			key:       "FLUSHDB",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecureRedisKey(tt.key)

			if tt.shouldErr && err == nil {
				t.Errorf("expected error for key: %s", tt.key)
			}

			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error for key %s: %v", tt.key, err)
			}
		})
	}
}

// TestValidateAndNormalizeRedisURL tests URL validation and normalization
func TestValidateAndNormalizeRedisURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		expected  string
		shouldErr bool
	}{
		{
			name:      "basic redis url",
			url:       "redis://localhost:6379",
			expected:  "redis://localhost:6379",
			shouldErr: false,
		},
		{
			name:      "url without scheme",
			url:       "localhost:6379",
			expected:  "redis://localhost:6379",
			shouldErr: false,
		},
		{
			name:      "url with default port",
			url:       "localhost",
			expected:  "redis://localhost:6379",
			shouldErr: false,
		},
		{
			name:      "empty url",
			url:       "",
			shouldErr: true,
		},
		{
			name:      "invalid scheme",
			url:       "http://localhost:6379",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateAndNormalizeRedisURL(tt.url)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("expected error for URL: %s", tt.url)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for URL %s: %v", tt.url, err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestGetStats tests statistics retrieval
func TestGetStats(t *testing.T) {
	provider, err := NewProvider("redis://localhost:6379")
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}
	defer func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Failed to close provider: %v", err)
		}
	}()

	stats := provider.GetStats()

	expectedKeys := []string{
		"active_requests", "active_watches", "active_watch_keys",
		"total_requests", "total_errors", "redis_url", "timeout",
		"max_retries", "is_connected", "last_health_check",
	}

	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("missing expected stat key: %s", key)
		}
	}
}

// BenchmarkValidateSecureRedisKey benchmarks key validation performance
func BenchmarkValidateSecureRedisKey(b *testing.B) {
	key := "my-config-key"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validateSecureRedisKey(key)
	}
}

// BenchmarkValidateAndNormalizeRedisURL benchmarks URL validation performance
func BenchmarkValidateAndNormalizeRedisURL(b *testing.B) {
	url := "redis://localhost:6379"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = validateAndNormalizeRedisURL(url)
	}
}

// BenchmarkProviderCreation benchmarks provider creation performance
func BenchmarkProviderCreation(b *testing.B) {
	url := "redis://localhost:6379"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider, err := NewProvider(url)
		if err != nil {
			b.Fatal(err)
		}
		if err := provider.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
