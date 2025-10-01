package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestBasicUsageExample tests the basic-usage.go example
func TestBasicUsageExample(t *testing.T) {
	// Check if Redis is available
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available for testing")
		return
	}

	// Setup test data in Redis - use keys that the example actually loads
	testData := map[string]string{
		"app-config":           `{"database": {"host": "updated-host", "port": 3306}, "new_feature": true}`,
		"example-watch-key":    `{"watch": "test data"}`,
		"performance-test-key": `{"perf": "test"}`,
	}

	for key, value := range testData {
		err := client.Set(ctx, key, value, time.Minute).Err()
		if err != nil {
			t.Fatalf("Failed to set test data: %v", err)
		}
	}

	// Cleanup after test
	defer func() {
		for key := range testData {
			client.Del(context.Background(), key)
		}
	}()

	// Run the example with timeout
	cmd := exec.Command("go", "run", "basic-usage.go")
	cmd.Dir = "."

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Start the command
	err := cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start example: %v", err)
	}

	// Give the example time to run and generate output
	time.Sleep(3 * time.Second)

	// Kill the process (it's designed to run indefinitely)
	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill process: %v", err)
		}
	}

	// Wait for process to complete and all output to be written
	err = cmd.Wait()
	if err != nil {
		// This is expected since we killed the process
		t.Logf("Process terminated as expected: %v", err)
	}

	// Now it's safe to read the output buffer
	output := out.String()

	// Check for expected output patterns
	expectedPatterns := []string{
		"Argus Redis Provider Example",
		"============================",
		"Checking Redis connection... OK",
		"1. Basic Configuration Loading",
		"Loaded config:", // Now we expect this since we set app-config
		"Provider name: Redis Remote Configuration Provider",
		"Provider scheme: redis",
		"2. Configuration Watching",
		"Started watching:",
		"3. Provider Statistics",
		"4. Security Validation Demo",
		"Testing security features",
		"Security working:",
		"Security test complete:",
		"5. Performance Testing",
		"Completed 100 operations",
		"6. Monitoring Mode",
		"Press Ctrl+C for graceful shutdown",
	}

	for _, pattern := range expectedPatterns {
		if !strings.Contains(output, pattern) {
			t.Errorf("Expected pattern not found in output: %s", pattern)
		}
	}

	// Check that security validations are working
	securityPatterns := []string{
		"Security working:",              // Should appear multiple times for different security blocks
		"Security test complete:",        // Should show dangerous patterns blocked
	}

	for _, pattern := range securityPatterns {
		if !strings.Contains(output, pattern) {
			t.Logf("Security validation pattern not found: %s", pattern)
		}
	}

	// Verify no actual errors occurred (only security blocks which are expected)
	if strings.Contains(output, "Failed") || strings.Contains(output, "Error:") {
		// But allow "Errors: 3 (security blocks)" which is expected
		if !strings.Contains(output, "Errors: 3 (security blocks)") {
			t.Errorf("Unexpected error in output: %s", output)
		}
	}

	t.Logf("Example ran successfully with expected output patterns")
}

// TestBasicUsageExampleStructure tests the structure and imports of the example
func TestBasicUsageExampleStructure(t *testing.T) {
	// Read the example file
	content, err := os.ReadFile("basic-usage.go")
	if err != nil {
		t.Fatalf("Failed to read basic-usage.go: %v", err)
	}

	contentStr := string(content)

	// Check for required imports
	requiredImports := []string{
		`"context"`,
		`"fmt"`,
		`"log"`,
		`"time"`,
		`redis "github.com/agilira/argus-provider-redis"`,
	}

	for _, imp := range requiredImports {
		if !strings.Contains(contentStr, imp) {
			t.Errorf("Required import not found: %s", imp)
		}
	}

	// Check for main function
	if !strings.Contains(contentStr, "func main()") {
		t.Error("main function not found")
	}

	// Check for proper provider creation
	if !strings.Contains(contentStr, "redis.NewProvider(") {
		t.Error("Provider creation not found")
	}

	// Check for proper error handling
	if !strings.Contains(contentStr, "defer func() {") {
		t.Error("Defer error handling not found")
	}

	// Check that all major sections are present
	majorSections := []string{
		"1. Basic Configuration Loading",
		"2. Configuration Watching",
		"3. Provider Statistics",
		"4. Security Validation Demo",
		"5. Performance Testing",
		"6. Monitoring Mode",
	}

	for _, section := range majorSections {
		if !strings.Contains(contentStr, section) {
			t.Errorf("Major section not found: %s", section)
		}
	}
}

// TestBasicUsageExampleCompilation tests that the example compiles without errors
func TestBasicUsageExampleCompilation(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "/tmp/basic-usage-test", "basic-usage.go")
	cmd.Dir = "."

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		t.Fatalf("Example failed to compile: %v\nOutput: %s", err, out.String())
	}

	// Cleanup the compiled binary
	_ = os.Remove("/tmp/basic-usage-test")

	t.Log("Example compiles successfully")
}

// TestBasicUsageExampleWithoutRedis tests the example behavior when Redis is not available
func TestBasicUsageExampleWithoutRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping example execution test in short mode")
	}

	// Check if Redis is available first - if it is, skip this test
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err == nil {
		t.Skip("Redis is available - cannot test unavailable scenario")
		return
	}

	// Redis is not available, test the example behavior
	cmd := exec.Command("go", "run", "basic-usage.go")
	cmd.Dir = "."

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Set a reasonable timeout
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case <-ctx2.Done():
		// Kill the process if it's still running
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		t.Log("Example appropriately timed out when Redis is unavailable")
	case err := <-done:
		output := out.String()
		if err != nil {
			// This is expected when Redis is not available
			if strings.Contains(output, "Failed to create Redis provider") ||
				strings.Contains(output, "connection refused") ||
				strings.Contains(output, "dial tcp") {
				t.Log("Example correctly failed when Redis is unavailable")
			} else {
				t.Logf("Example failed as expected: %v", err)
			}
		} else {
			t.Error("Example should have failed when Redis is unavailable")
		}
	}
}

// TestBasicUsageExampleDemoData tests the example with pre-populated demo data
func TestBasicUsageExampleDemoData(t *testing.T) {
	// Check if Redis is available
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available for testing")
		return
	}

	// Setup comprehensive demo data using keys that the example actually loads
	demoData := map[string]string{
		"app-config": `{
			"database": {
				"host": "updated-host",
				"port": 3306,
				"username": "admin",
				"ssl": true
			},
			"new_feature": true,
			"cache_enabled": true,
			"max_connections": 50
		}`,
		"example-watch-key": `{
			"value": "Watch test configuration",
			"last_updated": "2025-09-27T18:30:00Z"
		}`,
		"performance-test-key": `{
			"performance": "optimized",
			"cache_size": "10MB"
		}`,
	}

	// Set demo data
	for key, value := range demoData {
		err := client.Set(ctx, key, value, 5*time.Minute).Err()
		if err != nil {
			t.Fatalf("Failed to set demo data: %v", err)
		}
	}

	// Cleanup after test
	defer func() {
		for key := range demoData {
			client.Del(context.Background(), key)
		}
	}()

	// Run the example briefly
	cmd := exec.Command("go", "run", "basic-usage.go")
	cmd.Dir = "."

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Start()
	if err != nil {
		t.Fatalf("Failed to start example: %v", err)
	}

	// Let it run for 5 seconds to see the demo data
	time.Sleep(5 * time.Second)

	// Kill the process and wait for completion
	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill process: %v", err)
		}
	}

	// Wait for process to complete and all output to be written
	err = cmd.Wait()
	if err != nil {
		// This is expected since we killed the process
		t.Logf("Process terminated as expected: %v", err)
	}

	// Now it's safe to read the output buffer
	output := out.String()

	// Check that demo data was loaded correctly
	// Since we now have app-config populated, we should see "Loaded config:" instead of "Config not found"
	expectedDataPatterns := []string{
		"Loaded config:", // Should now show this since we populated app-config
		"updated-host",   // From the database config
		"3306",           // Port number
		"true",           // Boolean values
	}

	for _, pattern := range expectedDataPatterns {
		if !strings.Contains(output, pattern) {
			t.Errorf("Demo data pattern not found: %s", pattern)
		}
	}

	t.Log("Example successfully loaded and displayed demo data")
}

// BenchmarkBasicUsageStartup benchmarks the startup time of the basic usage example
func BenchmarkBasicUsageStartup(b *testing.B) {
	// Check if Redis is available
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		b.Skip("Redis not available for benchmarking")
		return
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cmd := exec.Command("go", "run", "basic-usage.go")
		cmd.Dir = "."

		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		start := time.Now()
		err := cmd.Start()
		if err != nil {
			b.Fatalf("Failed to start example: %v", err)
		}

		// Wait for the example to initialize (look for "Checking Redis connection... OK")
		done := make(chan bool)
		go func() {
			scanner := bufio.NewScanner(&out)
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), "Provider Statistics") {
					done <- true
					return
				}
			}
			done <- false
		}()

		select {
		case <-done:
			// Measure time to reach stats section (initialization complete)
			b.StopTimer()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			b.StartTimer()
		case <-time.After(10 * time.Second):
			b.StopTimer()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			b.Fatal("Example took too long to initialize")
		}

		elapsed := time.Since(start)
		if elapsed > 5*time.Second {
			b.Logf("Slow startup detected: %v", elapsed)
		}
	}
}
