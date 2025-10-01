# Argus Redis Provider Examples

This directory contains practical examples demonstrating how to use the Argus Redis Provider.

## Prerequisites

1. **Redis Server**: Make sure you have Redis running locally
   ```bash
   # Install Redis (Ubuntu/Debian)
   sudo apt install redis-server
   
   # Install Redis (macOS with Homebrew)
   brew install redis
   
   # Start Redis server
   redis-server
   
   # Or as a service
   sudo systemctl start redis
   ```

2. **Go Dependencies**: The examples will automatically download required dependencies
   ```bash
   go mod tidy
   ```

## Running the Examples

### Basic Usage Example

```bash
cd examples
go run basic-usage.go
```

This example demonstrates:
- Provider creation with configuration options
- Health checking with context support
- Configuration loading with proper URL format (`redis://host:port/key`)
- Real-time configuration watching with channels
- URL validation and security checks
- Performance statistics and monitoring
- Security validation (injection prevention)
- Performance testing with context

### Expected Output

```
Argus Redis Provider Example
============================

Checking Redis connection... OK

1. Basic Configuration Loading
------------------------------
Config not found (this is normal for first run): key not found

2. Configuration Watching
-------------------------
Started watching key: example-watch-key
To test watching, set a value in Redis:
  redis-cli SET example-watch-key "Hello, Argus!"

3. Provider Statistics
----------------------
  active_requests     : 0
  active_watches      : 1
  active_watch_keys   : 1
  total_requests      : 1
  total_errors        : 1
  redis_url          : redis://localhost:6379
  timeout            : 10s
  max_retries        : 3
  is_connected       : true
  last_health_check  : 2025-01-08 10:30:45.123456789 +0100 CET

4. Security Validation Demo
---------------------------
  ❌ '../etc/passwd' - BLOCKED: Redis key contains dangerous pattern: ..
  ❌ 'FLUSHDB' - BLOCKED: Redis key contains forbidden command: FLUSHDB
  ❌ 'config__set' - BLOCKED: Redis key contains dangerous pattern: __
  ✅ 'normal-key' - ALLOWED

5. Performance Testing
----------------------
Completed 100 operations in 15.234567ms
Average: 152.34567µs per operation

6. Monitoring Mode
------------------
Monitoring for 30 seconds... Change values in Redis to see live updates!
Requests: 101, Errors: 4, Watches: 1
Requests: 101, Errors: 4, Watches: 1
Requests: 101, Errors: 4, Watches: 1
Requests: 101, Errors: 4, Watches: 1
Requests: 101, Errors: 4, Watches: 1
Requests: 101, Errors: 4, Watches: 1

Example completed!
```

## Testing Live Configuration Changes

While the example is running in monitoring mode, open another terminal and try:

```bash
# Set a configuration value for watching
redis-cli SET example-watch-key "Hello from Redis!"

# Update it with JSON
redis-cli SET example-watch-key '{"app":"myapp","version":"1.0"}'

# Set another configuration
redis-cli SET app-config '{"database":{"host":"localhost","port":5432}}'

# The provider will automatically parse JSON and return proper map[string]interface{}
# For non-JSON values, it wraps them in: map["value": "your-string"]
```

You should see real-time updates in the example output:
```
Config changed: map[value:Hello from Redis!]
Config changed: map[app:myapp version:1.0]
```

## Argus Integration

The example shows how the Redis provider implements the Argus `RemoteConfigProvider` interface:

```go
// The provider implements all required methods:
provider.Name()                                    // "Redis Remote Configuration Provider v1.0"
provider.Scheme()                                  // "redis" 
provider.Validate("redis://localhost:6379/key")   // URL validation
provider.Load(ctx, "redis://localhost:6379/key")  // Load config with context
provider.Watch(ctx, "redis://localhost:6379/key") // Watch changes with channel
provider.HealthCheck(ctx, "redis://localhost:6379/key") // Health check with context
```

**Key differences from direct provider usage:**
- All methods now use **context** for timeout and cancellation
- URLs follow **Argus pattern**: `redis://host:port/key` (not just the key)
- `Load()` returns `map[string]interface{}` (not `interface{}`)
- `Watch()` returns a **channel** (not callback function)
- All operations are **thread-safe** and support concurrent usage

## Redis Configuration for Keyspace Notifications

For the watching feature to work properly, Redis needs keyspace notifications enabled:

```bash
# Enable keyspace notifications for all operations
redis-cli CONFIG SET notify-keyspace-events AKE

# Or add to redis.conf
echo "notify-keyspace-events AKE" >> /etc/redis/redis.conf
```

## Troubleshooting

### "Failed to create Redis provider: dial tcp 127.0.0.1:6379: connect: connection refused"

Redis is not running. Start Redis server:
```bash
redis-server
```

### "Config not found" errors

This is normal for first run. The examples are trying to load keys that don't exist yet.

### Watching not working

Make sure keyspace notifications are enabled in Redis:
```bash
redis-cli CONFIG SET notify-keyspace-events AKE
```

### Performance seems slow

- Check Redis server performance: `redis-cli --latency`
- Verify network connectivity
- Consider adjusting pool size and timeout settings

## Advanced Usage

The examples show basic usage. For production use, consider:

1. **TLS Configuration**
   ```go
   tlsConfig := &tls.Config{
       ServerName: "redis.example.com",
       MinVersion: tls.VersionTLS12,
   }
   provider, err := redis.NewProvider("rediss://redis.example.com:6380",
       redis.WithTLS(tlsConfig),
   )
   ```

2. **Redis Cluster**
   ```go
   provider, err := redis.NewProvider("redis://node1:6379,node2:6379,node3:6379")
   ```

3. **Connection Optimization**
   ```go
   provider, err := redis.NewProvider("redis://localhost:6379",
       redis.WithPoolSize(50),           // Larger pool for high concurrency
       redis.WithTimeout(30*time.Second), // Longer timeout for slow operations
       redis.WithMaxRetries(10),         // More retries for resilience
   )
   ```