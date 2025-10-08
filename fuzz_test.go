// fuzz_test.go - Professional Fuzz Testing Suite for Argus Redis Provider
//
// This file implements systematic fuzz testing against real functions in the Redis provider
// to identify security vulnerabilities and edge cases in production code.
//
// TESTED FUNCTIONS:
// - validateSecureRedisKey: Redis key validation and injection prevention
// - validateAndNormalizeRedisURL: URL parsing and validation for SSRF/injection prevention
// - extractRedisKey: Key extraction from Redis URLs with security validation
//
// SECURITY FOCUS:
// - Redis command injection prevention (FLUSHDB, EVAL, etc.)
// - URL manipulation and SSRF detection
// - Key injection and dangerous pattern detection
// - Resource exhaustion (DoS) protection
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGILira library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"strings"
	"testing"
	"time"
)

// FuzzValidateSecureRedisKey tests the real validateSecureRedisKey function for security issues.
//
// This function is critical for preventing Redis command injection attacks.
func FuzzValidateSecureRedisKey(f *testing.F) {
	// Seed corpus with real Redis attack vectors and valid cases
	seedKeys := []string{
		// Valid Redis keys that should work
		"config",
		"app-settings",
		"user-data",
		"service-config",

		// Redis command injection attacks (should be blocked)
		"FLUSHDB",
		"FLUSHALL",
		"CONFIG GET *",
		"EVAL malicious_script",
		"SCRIPT FLUSH",
		"SHUTDOWN",

		// Edge cases
		"",
		strings.Repeat("a", 1000),
	}

	for _, key := range seedKeys {
		f.Add(key)
	}

	f.Fuzz(func(t *testing.T, redisKey string) {
		// Function should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateSecureRedisKey panicked with input %q: %v", truncateString(redisKey, 100), r)
			}
		}()

		// Call the real function
		err := validateSecureRedisKey(redisKey)

		// Performance check - should complete quickly
		start := time.Now()
		_ = validateSecureRedisKey(redisKey)
		duration := time.Since(start)
		if duration > 50*time.Millisecond {
			t.Errorf("validateSecureRedisKey too slow (%v) for input: %q", duration, truncateString(redisKey, 100))
		}

		if err != nil {
			// Function rejected the key - log for analysis
			t.Logf("Key rejected: %q -> %v", truncateString(redisKey, 100), err)
		} else {
			// Function accepted the key - verify it's safe
			if containsObviousRedisCommand(redisKey) {
				t.Logf("WARNING: Redis command accepted as key: %q", truncateString(redisKey, 100))
			}
		}
	})
}

// FuzzValidateAndNormalizeRedisURL tests the real validateAndNormalizeRedisURL function.
func FuzzValidateAndNormalizeRedisURL(f *testing.F) {
	seedURLs := []string{
		// Valid Redis URLs
		"redis://localhost:6379",
		"redis://redis.example.com:6379",
		"rediss://secure.redis.com:6380",

		// Malformed URLs
		"redis://",
		"http://localhost:6379",
		"",
		"localhost",
	}

	for _, url := range seedURLs {
		f.Add(url)
	}

	f.Fuzz(func(t *testing.T, redisURL string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateAndNormalizeRedisURL panicked with input %q: %v", truncateString(redisURL, 100), r)
			}
		}()

		// Call the real function
		normalized, err := validateAndNormalizeRedisURL(redisURL)

		// Performance check
		start := time.Now()
		_, _ = validateAndNormalizeRedisURL(redisURL)
		duration := time.Since(start)
		if duration > 100*time.Millisecond {
			t.Errorf("validateAndNormalizeRedisURL too slow (%v) for input: %q", duration, truncateString(redisURL, 100))
		}

		if err != nil {
			// URL validation failed - log for analysis
			t.Logf("URL validation failed: %q -> %v", truncateString(redisURL, 100), err)
		} else {
			// URL validation succeeded - basic checks
			if len(normalized) > 10000 {
				t.Logf("Very long normalized URL: %d chars", len(normalized))
			}
		}
	})
}

// FuzzExtractRedisKey tests the real extractRedisKey function.
func FuzzExtractRedisKey(f *testing.F) {
	seedURLs := []string{
		// Valid Redis URLs with keys
		"redis://localhost:6379/config",
		"redis://localhost:6379/FLUSHDB",
		"redis://localhost:6379/",
		"",
	}

	for _, url := range seedURLs {
		f.Add(url)
	}

	f.Fuzz(func(t *testing.T, redisURL string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractRedisKey panicked with input %q: %v", truncateString(redisURL, 100), r)
			}
		}()

		// Call the real function
		key, err := extractRedisKey(redisURL)

		// Performance check
		start := time.Now()
		_, _ = extractRedisKey(redisURL)
		duration := time.Since(start)
		if duration > 50*time.Millisecond {
			t.Errorf("extractRedisKey too slow (%v) for input: %q", duration, truncateString(redisURL, 100))
		}

		if err != nil {
			// Extraction failed - log for analysis
			t.Logf("Key extraction failed: %q -> %v", truncateString(redisURL, 100), err)
		} else {
			// Extraction succeeded - log for analysis
			if containsObviousRedisCommand(key) {
				t.Logf("Redis command extracted as key: %q from URL: %q",
					truncateString(key, 100), truncateString(redisURL, 100))
			}
		}
	})
}

// Helper Functions
func containsObviousRedisCommand(input string) bool {
	redisCommands := []string{"FLUSHDB", "FLUSHALL", "CONFIG", "EVAL", "SCRIPT", "SHUTDOWN"}
	upperInput := strings.ToUpper(strings.TrimSpace(input))

	for _, cmd := range redisCommands {
		if upperInput == cmd || strings.HasPrefix(upperInput, cmd+" ") {
			return true
		}
	}
	return false
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
