/*
Package redis provides a high-performance Redis remote configuration provider for Argus.

This package implements the Argus RemoteConfigProvider interface to enable loading and watching
configuration from Redis Key-Value store with comprehensive security, performance optimizations,
and support for various Redis deployment modes including standalone, cluster, and sentinel.

# Basic Usage

	import "github.com/agilira/argus-provider-redis"

	// Create a new Redis provider
	provider, err := redis.NewProvider("redis://localhost:6379")
	if err != nil {
		log.Fatal(err)
	}
	defer provider.Close()

	// Load configuration
	value, err := provider.Load("my-config-key")
	if err != nil {
		log.Fatal(err)
	}

	// Watch for changes
	err = provider.Watch("my-config-key", func(newValue interface{}) {
		fmt.Printf("Config changed: %v\n", newValue)
	})

# Advanced Configuration

	provider, err := redis.NewProvider("redis://localhost:6379",
		redis.WithPassword("mypassword"),
		redis.WithDatabase(1),
		redis.WithTimeout(15*time.Second),
		redis.WithMaxRetries(5),
		redis.WithPoolSize(20),
	)

# TLS/SSL Support

	tlsConfig := &tls.Config{
		ServerName: "redis.example.com",
		MinVersion: tls.VersionTLS12,
	}

	provider, err := redis.NewProvider("rediss://redis.example.com:6380",
		redis.WithTLS(tlsConfig),
	)

# Redis Cluster Support

	provider, err := redis.NewProvider("redis://node1:6379,node2:6379,node3:6379")

# Security Features

The provider includes comprehensive security validation:
- Redis key injection prevention
- Forbidden command detection
- URL validation and normalization
- Response size limits (DoS protection)
- Concurrent request limits
- Secure connection handling

# Performance Features

- Pre-compiled security pattern matching
- Connection pooling with configurable limits
- Atomic counters for metrics
- Efficient watch mechanism using Redis pub/sub
- Response size validation
- Request timeout handling
- Health check caching

# Monitoring and Stats

	stats := provider.GetStats()
	fmt.Printf("Active requests: %v\n", stats["active_requests"])
	fmt.Printf("Total errors: %v\n", stats["total_errors"])

# Error Handling

The provider uses the go-errors library for structured error handling:
- 404 errors for missing keys
- Validation errors for security violations
- Network errors for connection issues
- Timeout errors for slow operations

# Redis URL Formats

Supported Redis URL formats:
- redis://localhost:6379 (standard)
- rediss://localhost:6380 (TLS/SSL)
- redis://username:password@localhost:6379/0 (with auth)
- redis://localhost:6379,localhost:6380 (cluster)
- unix:///tmp/redis.sock (Unix socket)

Copyright (c) 2025 AGILira - A. Giordano
Series: an AGILira library
SPDX-License-Identifier: MPL-2.0
*/
package redis
