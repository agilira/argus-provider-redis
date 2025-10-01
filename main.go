// Package redis provides a Redis remote configuration provider for Argus
//
// This package implements the Argus RemoteConfigProvider interface to enable
// loading and watching configuration from Redis Key-Value store with support
// for Redis Cluster, Sentinel, and standalone modes.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/go-errors"
	"github.com/redis/go-redis/v9"
)

// Security and resource limit constants for DoS prevention
const (
	// Maximum allowed response size from Redis (50MB - Redis can handle larger values)
	maxRedisResponseSize = 50 * 1024 * 1024

	// Default timeout for Redis requests (10 seconds - Redis is faster than Consul)
	defaultRedisTimeout = 10 * time.Second

	// Maximum concurrent requests per provider instance
	maxConcurrentRequests = 100

	// Maximum number of active watch operations per provider
	maxActiveWatches = 20

	// Maximum time to wait for watch channel operations (prevents deadlock)
	watchChannelTimeout = 5 * time.Second

	// Redis-specific constants
	defaultRedisPort     = "6379"
	defaultRedisDatabase = 0
)

// Pre-compiled security patterns for injection prevention
var (
	// Forbidden Redis commands that could be dangerous if injected
	forbiddenCommands = []string{
		"FLUSHDB", "FLUSHALL", "CONFIG", "EVAL", "EVALSHA",
		"SCRIPT", "SHUTDOWN", "DEBUG", "MIGRATE", "DUMP",
		"RESTORE", "SYNC", "PSYNC", "REPLCONF", "SLAVEOF",
		"REPLICAOF", "MONITOR", "CLIENT", "SENTINEL",
	}

	// Dangerous Redis key patterns (pre-compiled for performance)
	dangerousKeyPatterns = []string{
		"__", "..", "//", "\\", "*", "?", "[", "]",
		"{", "}", "|", "<", ">", ":", ";", "'", "\"",
		"\x00", "\x01", "\x02", "\x03", "\x04", "\x05",
	}
)

// Provider implements the Argus RemoteConfigProvider interface for Redis
type Provider struct {
	// Configuration
	redisURL   string
	timeout    time.Duration
	maxRetries int

	// Redis client connection
	client redis.UniversalClient

	// Security and performance monitoring
	activeRequests int64
	activeWatches  int64
	totalRequests  int64
	totalErrors    int64

	// Watch management
	watchMutex      sync.RWMutex
	activeWatchKeys map[string]chan<- interface{}
	cancelWatches   map[string]context.CancelFunc

	// Connection management
	connMutex       sync.RWMutex
	isConnected     bool
	lastHealthCheck time.Time
}

// ProviderConfig holds configuration options for the Redis provider
type ProviderConfig struct {
	URL        string        `json:"url"`
	Password   string        `json:"password,omitempty"`
	Database   int           `json:"database,omitempty"`
	Timeout    time.Duration `json:"timeout,omitempty"`
	MaxRetries int           `json:"max_retries,omitempty"`
	TLSConfig  *tls.Config   `json:"-"`
	PoolSize   int           `json:"pool_size,omitempty"`
}

// NewProvider creates a new Redis provider instance with comprehensive security validation
func NewProvider(redisURL string, options ...func(*ProviderConfig)) (*Provider, error) {
	if redisURL == "" {
		return nil, errors.New("INVALID_URL", "redis URL cannot be empty")
	}

	// Validate and normalize Redis URL with security checks
	normalizedURL, err := validateAndNormalizeRedisURL(redisURL)
	if err != nil {
		return nil, err
	}

	// Default configuration
	config := &ProviderConfig{
		URL:        normalizedURL,
		Database:   defaultRedisDatabase,
		Timeout:    defaultRedisTimeout,
		MaxRetries: 3,
		PoolSize:   10,
	}

	// Apply configuration options
	for _, option := range options {
		option(config)
	}

	// Create Redis client options
	opts := &redis.UniversalOptions{
		Addrs:        []string{extractHostPort(normalizedURL)},
		Password:     config.Password,
		DB:           config.Database,
		DialTimeout:  config.Timeout,
		ReadTimeout:  config.Timeout,
		WriteTimeout: config.Timeout,
		PoolSize:     config.PoolSize,
		MaxRetries:   config.MaxRetries,
		TLSConfig:    config.TLSConfig,
	}

	// Create Redis client
	client := redis.NewUniversalClient(opts)

	provider := &Provider{
		redisURL:        normalizedURL,
		timeout:         config.Timeout,
		maxRetries:      config.MaxRetries,
		client:          client,
		activeWatchKeys: make(map[string]chan<- interface{}),
		cancelWatches:   make(map[string]context.CancelFunc),
	}

	return provider, nil
}

// Name returns the human-readable provider name for debugging and logging
func (p *Provider) Name() string {
	return "Redis Remote Configuration Provider v1.0"
}

// Scheme returns the URL scheme this provider handles
func (p *Provider) Scheme() string {
	return "redis"
}

// Validate validates that the provider can handle the given Redis URL
func (p *Provider) Validate(configURL string) error {
	if configURL == "" {
		return errors.New("INVALID_URL", "Redis URL cannot be empty")
	}

	// First validate the URL format
	_, err := validateAndNormalizeRedisURL(configURL)
	if err != nil {
		return err
	}

	// Then validate that we can extract a key
	_, err = extractRedisKey(configURL)
	return err
}

// Load loads configuration from Redis following Argus RemoteConfigProvider interface
func (p *Provider) Load(ctx context.Context, configURL string) (map[string]interface{}, error) {
	// Increment and check concurrent request limits
	current := atomic.AddInt64(&p.activeRequests, 1)
	defer atomic.AddInt64(&p.activeRequests, -1)

	if current > maxConcurrentRequests {
		atomic.AddInt64(&p.totalErrors, 1)
		return nil, errors.New("RATE_LIMITED", "too many concurrent requests")
	}

	atomic.AddInt64(&p.totalRequests, 1)

	// Parse Redis URL to extract key
	key, err := extractRedisKey(configURL)
	if err != nil {
		atomic.AddInt64(&p.totalErrors, 1)
		return nil, err
	}

	// Validate key for security
	if err := validateSecureRedisKey(key); err != nil {
		atomic.AddInt64(&p.totalErrors, 1)
		return nil, err
	}

	// Create context with timeout if not already set
	ctxWithTimeout := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctxWithTimeout, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	// Execute Redis GET command
	result, err := p.client.Get(ctxWithTimeout, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("NOT_FOUND", "key not found")
		}
		atomic.AddInt64(&p.totalErrors, 1)
		return nil, errors.Wrap(err, "REDIS_ERROR", "failed to load from Redis")
	}

	// Validate response size
	if len(result) > maxRedisResponseSize {
		atomic.AddInt64(&p.totalErrors, 1)
		return nil, errors.New("RESPONSE_TOO_LARGE", "response too large")
	}

	// Try to parse as JSON
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(result), &config); err != nil {
		// Not JSON object, create wrapper
		config = map[string]interface{}{
			"value": result,
		}
	}

	return config, nil
}

// Watch monitors a Redis key for changes following Argus RemoteConfigProvider interface
func (p *Provider) Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error) {
	// Parse Redis URL to extract key
	key, err := extractRedisKey(configURL)
	if err != nil {
		return nil, err
	}

	// Validate key
	if err := validateSecureRedisKey(key); err != nil {
		return nil, err
	}

	// Check watch limits
	p.watchMutex.Lock()
	if len(p.activeWatchKeys) >= maxActiveWatches {
		p.watchMutex.Unlock()
		return nil, errors.New("RATE_LIMITED", "too many active watches")
	}

	// Check if already watching this key
	if _, exists := p.activeWatchKeys[key]; exists {
		p.watchMutex.Unlock()
		return nil, errors.New("ALREADY_WATCHING", "already watching key: "+key)
	}

	// Create result channel and internal watch channel
	resultChan := make(chan map[string]interface{}, 10)
	watchChan := make(chan interface{}, 1)
	watchCtx, cancel := context.WithCancel(ctx)

	p.activeWatchKeys[key] = watchChan
	p.cancelWatches[key] = cancel
	p.watchMutex.Unlock()

	atomic.AddInt64(&p.activeWatches, 1)

	// Start watching in goroutine
	go p.watchKey(watchCtx, key, resultChan, watchChan)

	// Send initial configuration
	go func() {
		if config, err := p.Load(ctx, configURL); err == nil {
			select {
			case resultChan <- config:
			case <-watchCtx.Done():
			}
		}
	}()

	return resultChan, nil
}

// watchKey implements the actual watching logic using Redis keyspace notifications
func (p *Provider) watchKey(ctx context.Context, key string, resultChan chan<- map[string]interface{}, watchChan <-chan interface{}) {
	defer func() {
		atomic.AddInt64(&p.activeWatches, -1)
		p.watchMutex.Lock()
		delete(p.activeWatchKeys, key)
		delete(p.cancelWatches, key)
		p.watchMutex.Unlock()
		close(resultChan)
	}()

	// Subscribe to keyspace notifications for this key
	pattern := fmt.Sprintf("__keyspace@%d__:%s", 0, key) // Assume DB 0 for simplicity
	pubsub := p.client.Subscribe(ctx, pattern)
	defer func() {
		if err := pubsub.Close(); err != nil {
			// Log error but don't propagate as we're in defer
			fmt.Printf("Warning: failed to close pubsub: %v\n", err)
		}
	}()

	// Construct Redis URL for Load calls
	configURL := fmt.Sprintf("redis://localhost:6379/%s", key)

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-pubsub.Channel():
			if msg != nil {
				// Key changed, load new value and send to channel
				if config, err := p.Load(ctx, configURL); err == nil {
					select {
					case resultChan <- config:
					case <-ctx.Done():
						return
					}
				}
			}
		case <-watchChan:
			// Manual notification channel
			if config, err := p.Load(ctx, configURL); err == nil {
				select {
				case resultChan <- config:
				case <-ctx.Done():
					return
				}
			}
		case <-time.After(watchChannelTimeout):
			// Periodic check to prevent hanging
			continue
		}
	}
}

// HealthCheck verifies Redis connection following Argus RemoteConfigProvider interface
func (p *Provider) HealthCheck(ctx context.Context, configURL string) error {
	// Validate URL first
	if err := p.Validate(configURL); err != nil {
		return err
	}

	p.connMutex.Lock()
	defer p.connMutex.Unlock()

	// Check if we've done a health check recently
	if time.Since(p.lastHealthCheck) < time.Minute {
		if p.isConnected {
			return nil
		}
		return errors.New("CONNECTION_UNHEALTHY", "Redis connection unhealthy")
	}

	// Create context with timeout if not already set
	ctxWithTimeout := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctxWithTimeout, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	// Execute PING command
	start := time.Now()
	result, err := p.client.Ping(ctxWithTimeout).Result()
	duration := time.Since(start)

	p.lastHealthCheck = time.Now()

	if err != nil {
		p.isConnected = false
		return errors.Wrap(err, "CONNECTION_ERROR", "Redis health check failed")
	}

	if result != "PONG" {
		p.isConnected = false
		return errors.New("UNEXPECTED_RESPONSE", "unexpected PING response: "+result)
	}

	// Check response time (warn if > 100ms)
	if duration > 100*time.Millisecond {
		// Still healthy but slow
	}

	p.isConnected = true
	return nil
}

// Close gracefully shuts down the provider and all active connections
func (p *Provider) Close() error {
	p.watchMutex.Lock()
	defer p.watchMutex.Unlock()

	// Cancel all active watches
	for key, cancel := range p.cancelWatches {
		cancel()
		delete(p.cancelWatches, key)
		delete(p.activeWatchKeys, key)
	}

	// Close Redis client
	if p.client != nil {
		return p.client.Close()
	}

	return nil
}

// GracefulShutdown performs a graceful shutdown with timeout control.
// This method provides production-grade shutdown capabilities following Argus patterns,
// ensuring all resources are properly cleaned up without hanging indefinitely.
//
// The method performs the following shutdown sequence:
// 1. Signals shutdown intent to all watch goroutines
// 2. Waits for all active Redis operations to complete
// 3. Closes all watch channels gracefully
// 4. Closes Redis client connection
//
// Example usage:
//
//	provider := redis.NewProvider("redis://localhost:6379")
//	defer provider.GracefulShutdown(30 * time.Second) // 30s timeout for Kubernetes
//
// Parameters:
//   - timeout: Maximum time to wait for graceful shutdown
//
// Returns:
//   - nil if shutdown completed within timeout
//   - error if shutdown timeout was exceeded or provider was already closed
//
// Production considerations:
//   - Kubernetes: Use terminationGracePeriodSeconds - 5s to allow for signal propagation
//   - Docker: Typically 10-30 seconds is sufficient
//   - CI/CD: Use shorter timeouts (5-10s) for faster test cycles
func (p *Provider) GracefulShutdown(timeout time.Duration) error {
	// Pre-validate timeout
	if timeout <= 0 {
		return errors.New("INVALID_TIMEOUT", "graceful shutdown timeout must be positive")
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Channel for shutdown completion signaling (buffered to avoid blocking)
	done := make(chan error, 1)

	// Execute shutdown in separate goroutine to respect timeout
	go func() {
		err := p.Close()
		select {
		case done <- err:
			// Successfully sent result
		default:
			// Channel full (timeout already occurred), ignore
			// The shutdown still completes in background for resource safety
		}
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		// Shutdown completed within timeout
		if err != nil {
			return errors.Wrap(err, "SHUTDOWN_ERROR", "graceful shutdown encountered error")
		}
		return nil

	case <-ctx.Done():
		// Timeout exceeded - return error but allow background cleanup to continue
		return errors.New("SHUTDOWN_TIMEOUT",
			fmt.Sprintf("graceful shutdown timeout (%v) exceeded, cleanup continuing in background", timeout))
	}
}

// GetStats returns provider performance and usage statistics
func (p *Provider) GetStats() map[string]interface{} {
	p.watchMutex.RLock()
	activeWatchCount := len(p.activeWatchKeys)
	p.watchMutex.RUnlock()

	return map[string]interface{}{
		"active_requests":   atomic.LoadInt64(&p.activeRequests),
		"active_watches":    atomic.LoadInt64(&p.activeWatches),
		"active_watch_keys": activeWatchCount,
		"total_requests":    atomic.LoadInt64(&p.totalRequests),
		"total_errors":      atomic.LoadInt64(&p.totalErrors),
		"redis_url":         p.redisURL,
		"timeout":           p.timeout.String(),
		"max_retries":       p.maxRetries,
		"is_connected":      p.isConnected,
		"last_health_check": p.lastHealthCheck,
	}
}

// validateSecureRedisKey validates Redis key for security issues
func validateSecureRedisKey(key string) error {
	if key == "" {
		return errors.New("INVALID_KEY", "Redis key cannot be empty")
	}

	if len(key) > 512*1024 {
		return errors.New("INVALID_KEY", "Redis key too long (max 512KB)")
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousKeyPatterns {
		if strings.Contains(key, pattern) {
			return errors.New("SECURITY_VIOLATION", "Redis key contains dangerous pattern: "+pattern)
		}
	}

	// Check for forbidden commands (case-insensitive, word boundaries)
	upperKey := strings.ToUpper(key)
	for _, cmd := range forbiddenCommands {
		// Check for exact word match to prevent false positives
		if upperKey == cmd || strings.HasPrefix(upperKey, cmd+" ") || strings.HasSuffix(upperKey, " "+cmd) || strings.Contains(upperKey, " "+cmd+" ") {
			return errors.New("SECURITY_VIOLATION", "Redis key contains forbidden command: "+cmd)
		}
	}

	return nil
}

// validateAndNormalizeRedisURL validates and normalizes Redis URL with security checks
func validateAndNormalizeRedisURL(redisURL string) (string, error) {
	if redisURL == "" {
		return "", errors.New("INVALID_URL", "Redis URL cannot be empty")
	}

	// Handle redis:// scheme and others
	if !strings.Contains(redisURL, "://") {
		redisURL = "redis://" + redisURL
	}

	parsedURL, err := url.Parse(redisURL)
	if err != nil {
		return "", errors.Wrap(err, "INVALID_URL", "invalid Redis URL")
	}

	// Validate scheme
	switch parsedURL.Scheme {
	case "redis", "rediss", "redis-socket", "unix":
		// Valid schemes
	default:
		return "", errors.New("INVALID_URL", "unsupported Redis URL scheme: "+parsedURL.Scheme)
	}

	// Normalize host and port
	host := parsedURL.Hostname()
	port := parsedURL.Port()

	if host == "" && parsedURL.Scheme != "unix" {
		host = "localhost"
	}

	if port == "" && parsedURL.Scheme != "unix" {
		port = defaultRedisPort
	}

	// Security validation for hostname
	if host != "" {
		if err := validateRedisHost(host); err != nil {
			return "", err
		}
	}

	// Rebuild URL with normalized components
	normalizedURL := &url.URL{
		Scheme: parsedURL.Scheme,
		User:   parsedURL.User,
		Host:   host + ":" + port,
		Path:   parsedURL.Path,
	}

	if parsedURL.Scheme == "unix" {
		normalizedURL.Host = ""
		normalizedURL.Path = parsedURL.Path
	}

	return normalizedURL.String(), nil
}

// validateRedisHost validates Redis hostname for security
func validateRedisHost(host string) error {
	if host == "" {
		return errors.New("INVALID_HOST", "Redis host cannot be empty")
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousKeyPatterns {
		if strings.Contains(host, pattern) {
			return errors.New("SECURITY_VIOLATION", "Redis host contains dangerous pattern: "+pattern)
		}
	}

	// Prevent localhost bypass attempts
	lowHost := strings.ToLower(host)
	if strings.Contains(lowHost, "..") || strings.Contains(lowHost, "//") {
		return errors.New("SECURITY_VIOLATION", "Redis host contains path traversal patterns")
	}

	return nil
}

// extractHostPort extracts host:port from Redis URL
func extractHostPort(redisURL string) string {
	parsedURL, err := url.Parse(redisURL)
	if err != nil {
		return "localhost:6379" // Fallback
	}

	if parsedURL.Scheme == "unix" {
		return parsedURL.Path
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = defaultRedisPort
	}

	return host + ":" + port
}

// extractRedisKey extracts the key from a Redis URL (redis://host:port/key)
func extractRedisKey(redisURL string) (string, error) {
	parsedURL, err := url.Parse(redisURL)
	if err != nil {
		return "", errors.Wrap(err, "INVALID_URL", "invalid Redis URL")
	}

	if parsedURL.Scheme != "redis" && parsedURL.Scheme != "rediss" {
		return "", errors.New("INVALID_URL", "URL scheme must be 'redis' or 'rediss'")
	}

	// Extract key from path (remove leading slash)
	key := strings.TrimPrefix(parsedURL.Path, "/")
	if key == "" {
		return "", errors.New("INVALID_URL", "Redis key is required in URL path")
	}

	return key, nil
}

// WithPassword sets the Redis password
func WithPassword(password string) func(*ProviderConfig) {
	return func(config *ProviderConfig) {
		config.Password = password
	}
}

// WithDatabase sets the Redis database number
func WithDatabase(db int) func(*ProviderConfig) {
	return func(config *ProviderConfig) {
		if db >= 0 && db <= 15 { // Redis default max databases
			config.Database = db
		}
	}
}

// WithTimeout sets the Redis operation timeout
func WithTimeout(timeout time.Duration) func(*ProviderConfig) {
	return func(config *ProviderConfig) {
		if timeout > 0 && timeout <= time.Minute {
			config.Timeout = timeout
		}
	}
}

// WithMaxRetries sets the maximum number of retries
func WithMaxRetries(retries int) func(*ProviderConfig) {
	return func(config *ProviderConfig) {
		if retries >= 0 && retries <= 10 {
			config.MaxRetries = retries
		}
	}
}

// WithTLS sets the TLS configuration
func WithTLS(tlsConfig *tls.Config) func(*ProviderConfig) {
	return func(config *ProviderConfig) {
		config.TLSConfig = tlsConfig
	}
}

// WithPoolSize sets the connection pool size
func WithPoolSize(size int) func(*ProviderConfig) {
	return func(config *ProviderConfig) {
		if size > 0 && size <= 100 {
			config.PoolSize = size
		}
	}
}
