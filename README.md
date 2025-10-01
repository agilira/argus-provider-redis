# Argus Provider Redis

![Go Version](https://img.shields.io/badge/go-1.25%2B-blue)
![License](https://img.shields.io/badge/license-MPL--2.0-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

A high-performance Redis remote configuration provider for the Argus configuration management system.

## Features

🚀 **High Performance**
- Pre-compiled security patterns for zero-allocation validation
- Efficient connection pooling with configurable limits
- Atomic counters for real-time metrics
- Optimized watch mechanism using Redis pub/sub

🔒 **Security First**
- Redis injection prevention
- Forbidden command detection  
- URL validation and normalization
- Response size limits (DoS protection)
- Concurrent request limits

🏗️ **Redis Support**
- Standalone Redis servers
- Redis Cluster mode
- Redis Sentinel
- Unix socket connections
- TLS/SSL encrypted connections
- Authentication support

📊 **Monitoring & Observability**
- Real-time performance metrics
- Health check endpoints
- Connection status monitoring
- Request/error counters

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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the Mozilla Public License 2.0 - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [Argus](https://github.com/agilira/argus) - Main configuration management system
- [Argus Provider Consul](https://github.com/agilira/argus-provider-consul) - Consul provider
- [go-errors](https://github.com/agilira/go-errors) - Structured error handling

## Support

For questions and support:
- Create an issue on GitHub
- Check the documentation in `doc.go`
- Review the examples in the `examples/` directory

---

**AGILira Series** - A. Giordano  
Copyright (c) 2025 - Licensed under MPL-2.0