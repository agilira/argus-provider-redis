# Security Policy

## Reporting a Vulnerability

We greatly value the efforts of the community in identifying and responsibly disclosing security vulnerabilities. Your contributions help us ensure the safety and reliability of our software.

If you have discovered a vulnerability in one of our products or have security concerns regarding AGILira software, please contact us at **security@agilira.com**.

To help us address your report effectively, please include the following details:

- **Steps to Reproduce**: A clear and concise description of how to reproduce the issue or a proof-of-concept.
- **Relevant Tools**: Any tools used during your investigation, including their versions.
- **Tool Output**: Logs, screenshots, or any other output that supports your findings.

For more information about AGILira's security practices, please visit our [Security Page](https://agilira.one/security).

Thank you for helping us maintain a secure and trustworthy environment for all users.

## Security Testing and Fuzz Testing

### Overview

The Argus Redis Provider undergoes comprehensive security testing including static analysis, dynamic testing, and **fuzz testing** to identify potential vulnerabilities and ensure robust security in production environments.

### Fuzz Testing Implementation

This provider includes comprehensive fuzz testing implemented with Go's native fuzzing framework (Go 1.18+) to test critical security boundaries specific to Redis operations:

#### Fuzz Test Functions

1. **`FuzzValidateAndNormalizeRedisURL`** - Tests Redis URL validation security
   - **Attack Surface**: URL parsing and normalization for Redis connections
   - **Security Coverage**: SSRF prevention, Redis protocol injection, authentication bypass detection
   - **Seed Corpus**: Redis-specific URL formats, cluster configurations, sentinel setups, malicious URLs

2. **`FuzzValidateSecureRedisKey`** - Tests Redis key injection prevention
   - **Attack Surface**: Redis key validation and sanitization  
   - **Security Coverage**: Redis command injection (FLUSHDB, EVAL, CONFIG), dangerous pattern detection
   - **Seed Corpus**: Redis commands, injection attempts, encoded payloads, binary data

3. **`FuzzExtractRedisKey`** - Tests key extraction from URLs
   - **Attack Surface**: URL path processing for Redis key extraction
   - **Security Coverage**: Path traversal prevention, URL encoding bypass, key namespace protection
   - **Seed Corpus**: Malformed URLs, traversal attempts, encoded keys

4. **`FuzzRedisJSONParsing`** - Tests JSON parser resilience  
   - **Attack Surface**: JSON parsing from Redis server responses
   - **Security Coverage**: Memory exhaustion prevention, Redis-specific data type handling, oversized value protection
   - **Seed Corpus**: Large Redis values (up to 50MB), deeply nested structures, Redis command injection via JSON

5. **`FuzzRedisProviderLoad`** - Tests end-to-end provider functionality
   - **Attack Surface**: Complete Redis configuration loading process
   - **Security Coverage**: Integrated security validation, error handling safety, resource management
   - **Seed Corpus**: Malicious URLs, invalid configurations, Redis-specific edge cases

### Redis-Specific Security Considerations

#### Redis Command Injection Prevention
Redis supports powerful commands that can compromise system security:

**Critical Commands Blocked**:
- `FLUSHDB` / `FLUSHALL` - Database/server data deletion
- `CONFIG` - Server configuration manipulation  
- `EVAL` / `EVALSHA` / `SCRIPT` - Lua script execution
- `SHUTDOWN` - Server termination
- `DEBUG` - Debug commands with system access
- `MIGRATE` / `DUMP` / `RESTORE` - Data migration commands
- `SYNC` / `PSYNC` / `MONITOR` - Replication and monitoring
- `CLIENT` / `SENTINEL` - Client and sentinel management

#### Binary Data Handling
Redis keys and values can contain binary data, requiring special security handling:
- **Null Byte Injection**: Prevention of `\x00` in keys
- **Control Characters**: Filtering dangerous control characters
- **Protocol Confusion**: Preventing RESP protocol injection
- **Large Value Handling**: Safe processing of Redis's 512MB value limit

### Running Fuzz Tests

#### Quick Fuzz Testing (30 seconds each test)
```bash
make fuzz
```

#### Extended Fuzz Testing (5 minutes each test - recommended for CI)
```bash
make fuzz-extended  
```

#### Continuous Fuzz Testing (until interrupted)
```bash
make fuzz-continuous
```

#### Security-Focused CI Pipeline
```bash
make ci-security  # Includes static analysis + fuzz testing
```

### Interpreting Fuzz Test Results

#### Successful Fuzz Run
```
fuzz: elapsed: 30s, gathering baseline coverage: 0s, corpus: 234 (now: 234), crashers: 0
```
- **No crashers**: All inputs handled safely
- **Higher corpus**: Redis handles more input variety than other protocols
- **Baseline coverage**: Code paths exercised including Redis-specific logic

#### Fuzz Failure Indicators
```
fuzz: elapsed: 8s, gathering baseline coverage: 0s, corpus: 45 (now: 45), crashers: 1
```
- **crashers > 0**: Security vulnerability or crash found
- **Check testdata/fuzz/**: Contains failing inputs
- **Review crash logs**: Identify root cause (often Redis command injection)

#### Redis-Specific Security Violations
Look for these patterns in fuzz output:
- `SECURITY VIOLATION: Redis command` - Command injection detected
- `SECURITY VIOLATION: Dangerous pattern` - Suspicious Redis key patterns
- `SECURITY LEAK: Redis command in error` - Command exposure in error messages
- `RESOURCE VIOLATION: Response too large` - DoS via oversized Redis values

### Fuzz Test Security Coverage  

#### URL Validation Security (validateAndNormalizeRedisURL)
- **Redis Scheme Validation**: Enforces redis://, rediss://, unix:// schemes
- **Cluster/Sentinel Support**: Validates multi-node configurations safely
- **SSRF Prevention**: Blocks connections to internal services and metadata endpoints
- **Authentication Security**: Protects Redis AUTH credentials from exposure
- **Protocol Injection**: Prevents Redis protocol (RESP) manipulation

#### Redis Key Security (validateSecureRedisKey)
- **Command Injection Prevention**: Blocks all dangerous Redis commands
- **Binary Data Safety**: Handles binary keys without protocol confusion  
- **Pattern Validation**: Detects Redis-specific dangerous patterns (*, ?, [], {})
- **Length Limits**: Enforces Redis key size limits (512KB max)
- **Namespace Protection**: Prevents key namespace escape attempts

#### Key Extraction Security (extractRedisKey)
- **URL Path Validation**: Safely extracts keys from Redis URL paths
- **Encoding Safety**: Handles URL encoding without bypass vulnerabilities
- **Multi-segment Keys**: Properly processes complex Redis key structures
- **Protocol Separation**: Maintains distinction between URL and Redis protocol

#### JSON Parser Security (Redis JSON parsing)
- **Large Value Handling**: Safely processes Redis's large value capability (512MB)
- **Redis Data Types**: Properly handles Redis-specific data type representations
- **Command Injection in JSON**: Detects Redis commands embedded in configuration values
- **Memory Management**: Prevents memory exhaustion with oversized Redis responses

### Security Testing Best Practices

1. **Redis-Specific Testing**: Focus on Redis protocol and command injection
2. **Large Data Testing**: Use `fuzz-extended` for Redis's large value handling
3. **Multi-Instance Testing**: Test Redis Cluster and Sentinel configurations
4. **Binary Data Testing**: Include binary data in fuzz corpus
5. **Protocol Testing**: Validate RESP protocol handling safety

### Integration with Red Team Testing

Redis-specific security testing includes:
- **Static Analysis**: gosec, staticcheck for Redis client vulnerabilities
- **Vulnerability Scanning**: govulncheck for known CVEs in Redis dependencies
- **Dynamic Testing**: Fuzz testing for Redis protocol and command safety
- **Red Team Testing**: Manual Redis security assessment and penetration testing
- **Protocol Testing**: RESP protocol manipulation and injection testing
- **Configuration Security**: Redis configuration parameter validation

### Redis Security Threat Model

#### Primary Attack Vectors
1. **Command Injection**: Malicious Redis commands in keys/values
2. **Protocol Injection**: RESP protocol manipulation
3. **Authentication Bypass**: Redis AUTH credential manipulation  
4. **Data Exfiltration**: Unauthorized access to Redis data
5. **DoS Attacks**: Resource exhaustion via large values or complex operations
6. **SSRF Attacks**: Using Redis as pivot for internal network access

#### Mitigations Implemented
1. **Comprehensive Key Validation**: Blocks all dangerous Redis commands
2. **URL Validation**: Prevents SSRF and protocol injection
3. **Resource Limits**: Enforces safe memory and processing limits
4. **Error Safety**: Prevents credential and command leakage in errors
5. **Protocol Separation**: Maintains clean separation between HTTP and Redis protocols

### Continuous Security Improvement

The Redis provider fuzz testing suite is continuously enhanced based on:
- **Redis Security Research**: Latest Redis vulnerability research and CVEs
- **Protocol Security**: RESP protocol security analysis and improvements  
- **Command Security**: Analysis of new Redis commands and their security implications
- **Community Research**: External security research specific to Redis
- **Real-World Attacks**: Analysis of actual Redis security incidents

For security issues found through fuzz testing or other means, please follow the vulnerability reporting process above.

---

argus-provider-redis • an AGILira library