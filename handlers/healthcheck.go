package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/stefanhall2704/GoPhotography/db"
)

// HealthStatus represents the overall health status
type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusDegraded  HealthStatus = "degraded"
	StatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheckResponse represents the health check response structure
type HealthCheckResponse struct {
	Status      HealthStatus            `json:"status"`
	Timestamp   time.Time               `json:"timestamp"`
	Version     string                  `json:"version"`
	Environment string                  `json:"environment"`
	Uptime      string                  `json:"uptime"`
	Components  map[string]ComponentHealth `json:"components"`
	Metrics     SystemMetrics           `json:"metrics"`
}

// ComponentHealth represents the health of individual components
type ComponentHealth struct {
	Status    HealthStatus `json:"status"`
	Message   string       `json:"message,omitempty"`
	Latency   string       `json:"latency,omitempty"`
	Details   interface{}  `json:"details,omitempty"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	MemoryUsage    MemoryInfo `json:"memory"`
	Goroutines     int        `json:"goroutines"`
	NumCPU         int        `json:"num_cpu"`
	GoVersion      string     `json:"go_version"`
}

// MemoryInfo represents memory usage information
type MemoryInfo struct {
	Alloc      uint64 `json:"alloc"`
	TotalAlloc uint64 `json:"total_alloc"`
	Sys        uint64 `json:"sys"`
	NumGC      uint32 `json:"num_gc"`
}

// DatabaseInfo represents database connection information
type DatabaseInfo struct {
	Driver          string `json:"driver"`
	Host            string `json:"host"`
	Port            string `json:"port"`
	Database        string `json:"database"`
	MaxOpenConns    int    `json:"max_open_conns"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	ConnMaxLifetime string `json:"conn_max_lifetime"`
	ConnMaxIdleTime string `json:"conn_max_idle_time"`
}

var startTime = time.Now()

// HealthCheck performs comprehensive health checks on all system components
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	response := HealthCheckResponse{
		Timestamp:   time.Now(),
		Version:     getVersion(),
		Environment: getEnvironment(),
		Uptime:      time.Since(startTime).String(),
		Components:  make(map[string]ComponentHealth),
		Metrics:     getSystemMetrics(),
	}

	// Check database health
	dbHealth := checkDatabaseHealth(ctx)
	response.Components["database"] = dbHealth

	// Check ingress/network connectivity
	networkHealth := checkNetworkHealth(ctx)
	response.Components["network"] = networkHealth

	// Check file system health
	fsHealth := checkFileSystemHealth()
	response.Components["filesystem"] = fsHealth

	// Check external services (if any)
	externalHealth := checkExternalServices(ctx)
	response.Components["external_services"] = externalHealth

	// Determine overall status
	response.Status = determineOverallStatus(response.Components)

	// Set appropriate HTTP status code
	statusCode := http.StatusOK
	if response.Status == StatusDegraded {
		statusCode = http.StatusOK // Still return 200 for degraded
	} else if response.Status == StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// checkDatabaseHealth checks the database connection and performance
func checkDatabaseHealth(ctx context.Context) ComponentHealth {
	start := time.Now()
	
	database := db.GetDB()
	if database == nil {
		return ComponentHealth{
			Status:  StatusUnhealthy,
			Message: "Database instance is nil",
		}
	}

	// Get underlying SQL database for connection pool info
	sqlDB, err := database.DB()
	if err != nil {
		return ComponentHealth{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("Failed to get SQL database: %v", err),
		}
	}

	// Test connection with timeout
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	if err := sqlDB.PingContext(pingCtx); err != nil {
		return ComponentHealth{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("Database ping failed: %v", err),
		}
	}

	// Get connection pool stats
	stats := sqlDB.Stats()
	
	// Check if we have available connections
	if stats.OpenConnections >= stats.MaxOpenConnections {
		return ComponentHealth{
			Status:  StatusDegraded,
			Message: "Database connection pool is at capacity",
			Latency: time.Since(start).String(),
			Details: DatabaseInfo{
				Driver:          "postgres",
				Host:            getEnv("DB_HOST", "localhost"),
				Port:            getEnv("DB_PORT", "5432"),
				Database:        getEnv("DB_NAME", "hallphotography"),
				MaxOpenConns:    stats.MaxOpenConnections,
				MaxIdleConns:    stats.Idle, // Use Idle field instead
				ConnMaxLifetime: "5m",
				ConnMaxIdleTime: "10m",
			},
		}
	}

	return ComponentHealth{
		Status:  StatusHealthy,
		Message: "Database connection is healthy",
		Latency: time.Since(start).String(),
		Details: DatabaseInfo{
			Driver:          "postgres",
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			Database:        getEnv("DB_NAME", "hallphotography"),
			MaxOpenConns:    stats.MaxOpenConnections,
			MaxIdleConns:    stats.Idle, // Use Idle field instead
			ConnMaxLifetime: "5m",
			ConnMaxIdleTime: "10m",
		},
	}
}

// checkNetworkHealth checks network connectivity and ingress status
func checkNetworkHealth(ctx context.Context) ComponentHealth {
	start := time.Now()
	
	// Check if we can resolve the ingress hostname
	ingressHost := "photography.stefan-sre.com"
	
	resolver := &net.Resolver{}
	_, err := resolver.LookupHost(ctx, ingressHost)
	if err != nil {
		return ComponentHealth{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("Cannot resolve ingress hostname %s: %v", ingressHost, err),
			Latency: time.Since(start).String(),
		}
	}

	// Try to connect to the ingress host (HTTPS)
	conn, err := net.DialTimeout("tcp", ingressHost+":443", 5*time.Second)
	if err != nil {
		return ComponentHealth{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("Cannot connect to ingress on port 443: %v", err),
			Latency: time.Since(start).String(),
		}
	}
	conn.Close()

	// Check local server port
	localConn, err := net.DialTimeout("tcp", "localhost:8080", 2*time.Second)
	if err != nil {
		return ComponentHealth{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("Local server port 8080 not accessible: %v", err),
			Latency: time.Since(start).String(),
		}
	}
	localConn.Close()

	return ComponentHealth{
		Status:  StatusHealthy,
		Message: "Network connectivity is healthy",
		Latency: time.Since(start).String(),
		Details: map[string]interface{}{
			"ingress_host": ingressHost,
			"local_port":   "8080",
		},
	}
}

// checkFileSystemHealth checks file system health and permissions
func checkFileSystemHealth() ComponentHealth {
	start := time.Now()
	
	// Check if uploads directory exists and is writable
	uploadsDir := "uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		return ComponentHealth{
			Status:  StatusDegraded,
			Message: "Uploads directory does not exist",
			Latency: time.Since(start).String(),
		}
	}

	// Test write permissions
	testFile := uploadsDir + "/.healthcheck_test"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return ComponentHealth{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("Cannot write to uploads directory: %v", err),
			Latency: time.Since(start).String(),
		}
	}
	os.Remove(testFile) // Clean up

	// Check templates directory
	templatesDir := "templates"
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		return ComponentHealth{
			Status:  StatusUnhealthy,
			Message: "Templates directory does not exist",
			Latency: time.Since(start).String(),
		}
	}

	return ComponentHealth{
		Status:  StatusHealthy,
		Message: "File system is healthy",
		Latency: time.Since(start).String(),
		Details: map[string]interface{}{
			"uploads_writable":   true,
			"templates_accessible": true,
		},
	}
}

// checkExternalServices checks external service dependencies
func checkExternalServices(ctx context.Context) ComponentHealth {
	start := time.Now()
	
	// Check Google OAuth service (if configured)
	googleHealth := checkGoogleOAuth(ctx)
	
	// For now, we'll consider external services healthy if Google OAuth is accessible
	// You can add more external service checks here as needed
	
	return ComponentHealth{
		Status:  googleHealth,
		Message: "External services check completed",
		Latency: time.Since(start).String(),
		Details: map[string]interface{}{
			"google_oauth": googleHealth,
		},
	}
}

// checkGoogleOAuth checks Google OAuth service availability
func checkGoogleOAuth(ctx context.Context) HealthStatus {
	// Try to connect to Google OAuth endpoints
	conn, err := net.DialTimeout("tcp", "accounts.google.com:443", 5*time.Second)
	if err != nil {
		return StatusDegraded
	}
	conn.Close()
	return StatusHealthy
}

// determineOverallStatus determines the overall system health status
func determineOverallStatus(components map[string]ComponentHealth) HealthStatus {
	hasUnhealthy := false
	hasDegraded := false

	for _, component := range components {
		switch component.Status {
		case StatusUnhealthy:
			hasUnhealthy = true
		case StatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return StatusUnhealthy
	}
	if hasDegraded {
		return StatusDegraded
	}
	return StatusHealthy
}

// getSystemMetrics collects system-level metrics
func getSystemMetrics() SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return SystemMetrics{
		MemoryUsage: MemoryInfo{
			Alloc:      m.Alloc,
			TotalAlloc: m.TotalAlloc,
			Sys:        m.Sys,
			NumGC:      m.NumGC,
		},
		Goroutines: runtime.NumGoroutine(),
		NumCPU:     runtime.NumCPU(),
		GoVersion:  runtime.Version(),
	}
}

// getVersion returns the application version
func getVersion() string {
	// You can set this via build flags or environment variables
	if version := os.Getenv("APP_VERSION"); version != "" {
		return version
	}
	return "1.0.0"
}

// getEnvironment returns the current environment
func getEnvironment() string {
	if env := os.Getenv("ENVIRONMENT"); env != "" {
		return env
	}
	if env := os.Getenv("ENV"); env != "" {
		return env
	}
	return "development"
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
