# argus-provider-redis: Argus remote provider for Redis
### an AGILira library

The official high-performance [Redis](https://redis.io) provider for [Argus](https://github.com/agilira/argus). Provides real-time configuration loading, live watching capabilities, and professional-grade security features for production environments.

[![CI](https://github.com/agilira/argus-provider-redis/actions/workflows/ci.yml/badge.svg)](https://github.com/agilira/argus-provider-redis/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/Security-gosec-brightgreen)](https://github.com/agilira/argus-provider-redis/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/agilira/argus-provider-redis?v=2)](https://goreportcard.com/report/github.com/agilira/argus-provider-redis)
[![Coverage](https://codecov.io/gh/agilira/argus-provider-redis/branch/main/graph/badge.svg)](https://codecov.io/gh/agilira/argus-provider-redis)
[![Made For Argus](https://img.shields.io/badge/Made_for-Argus-87CEEB)](https://github.com/agilira/argus)

**[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Advanced Configuration](#advanced-configuration) • [Security Features](#security-features) • [Performance](#performance-optimizations) • [Monitoring](#monitoring)**

## Features

**High Performance**
- Pre-compiled security patterns for zero-allocation validation
- Efficient connection pooling with configurable limits
- Atomic counters for real-time metrics
- Optimized watch mechanism using Redis pub/sub

**Security First**
- Redis injection prevention
- Forbidden command detection  
- URL validation and normalization
- Response size limits (DoS protection)
- Concurrent request limits

**Redis Support**
- Standalone Redis servers
- Redis Cluster mode
- Redis Sentinel
- Unix socket connections
- TLS/SSL encrypted connections
- Authentication support

**Monitoring & Observability**
- Real-time performance metrics
- Health check endpoints
- Connection status monitoring
- Request/error counters

## Compatibility and Support

argus-provider-redis is designed to work with Redis 9+ and follows Long-Term Support guidelines to ensure consistent performance across production deployments.

## Installation

```bash
go get github.com/agilira/argus-provider-redis
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    redis "github.com/agilira/argus-provider-redis"
)

func main() {
    // Create provider
    provider, err := redis.NewProvider("redis://localhost:6379")
    if err != nil {
        log.Fatal(err)
    }
    defer provider.Close()

    // Load configuration
    value, err := provider.Load("app-config")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Config: %v\n", value)

    // Watch for changes
    err = provider.Watch("app-config", func(newValue interface{}) {
        fmt.Printf("Config updated: %v\n", newValue)
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

## Advanced Configuration

```go
provider, err := redis.NewProvider("redis://localhost:6379",
    redis.WithPassword("secure-password"),
    redis.WithDatabase(1),
    redis.WithTimeout(15*time.Second),
    redis.WithMaxRetries(5),
    redis.WithPoolSize(20),
)
```

## TLS/SSL Configuration

```go
tlsConfig := &tls.Config{
    ServerName: "redis.example.com",
    MinVersion: tls.VersionTLS12,
}

provider, err := redis.NewProvider("rediss://redis.example.com:6380",
    redis.WithTLS(tlsConfig),
)
```

## Redis Cluster Support

```go
provider, err := redis.NewProvider("redis://node1:6379,node2:6379,node3:6379")
```

## Monitoring

```go
// Get real-time statistics
stats := provider.GetStats()
fmt.Printf("Active requests: %v\n", stats["active_requests"])
fmt.Printf("Total errors: %v\n", stats["total_errors"])
fmt.Printf("Active watches: %v\n", stats["active_watches"])

// Health check
if err := provider.HealthCheck(); err != nil {
    log.Printf("Redis health check failed: %v", err)
}
```

## Security Features

### Key Validation
- Prevents Redis injection attacks
- Validates key length and patterns
- Blocks dangerous command injection

### Network Security  
- URL validation and normalization
- Host validation with security checks
- Path traversal prevention

### Resource Protection
- Maximum response size limits (50MB)
- Concurrent request limits (100 per instance)
- Active watch limits (20 per instance)
- Request timeout handling

## Performance Optimizations

### Pre-compiled Patterns
```go
// Zero-allocation security pattern matching
var dangerousKeyPatterns = []string{
    "__", "..", "//", "\\", "*", "?", "[", "]", 
    "{", "}", "|", "<", ">", ":", ";", "'", "\"",
}
```

### Efficient Metrics
```go
// Atomic counters for thread-safe metrics
atomic.AddInt64(&p.activeRequests, 1)
atomic.AddInt64(&p.totalRequests, 1)
```

### Connection Pooling
- Configurable pool size (default: 10)
- Connection reuse and management
- Automatic reconnection handling

## Error Handling

The provider uses structured errors with context:

```go
// 404 for missing keys
value, err := provider.Load("nonexistent-key")
// err will have code 404

// Security validation errors
err := provider.Load("../dangerous-key")  
// err: "Redis key contains dangerous pattern: .."

// Network timeouts
err := provider.Load("slow-key")
// err: wrapped timeout error with context
```

## Benchmarks

Performance benchmarks show significant optimizations:

```
BenchmarkLoad-8                  1000000    1205 ns/op     224 B/op       4 allocs/op
BenchmarkValidateKey-8          10000000     156 ns/op       0 B/op       0 allocs/op
BenchmarkWatch-8                  500000    2890 ns/op     512 B/op       8 allocs/op
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `WithPassword(string)` | "" | Redis authentication password |
| `WithDatabase(int)` | 0 | Redis database number (0-15) |
| `WithTimeout(duration)` | 10s | Operation timeout |
| `WithMaxRetries(int)` | 3 | Maximum retry attempts |
| `WithPoolSize(int)` | 10 | Connection pool size |
| `WithTLS(*tls.Config)` | nil | TLS configuration |

## URL Formats

Supported Redis connection URLs:

- `redis://localhost:6379` - Standard connection
- `rediss://localhost:6380` - TLS/SSL connection  
- `redis://user:pass@localhost:6379/1` - With authentication and database
- `redis://node1:6379,node2:6379,node3:6379` - Cluster mode
- `unix:///tmp/redis.sock` - Unix socket

## License

Mozilla Public License 2.0 - see the [LICENSE](LICENSE.md) file for details.

---

argus-provider-redis • an AGILira library