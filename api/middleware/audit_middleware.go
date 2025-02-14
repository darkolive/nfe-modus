package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"nfe-modus/api/functions/audit"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/http"
)

type User struct {
	ID        string
	Email     string
	IPAddress string
	Country   string
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	MaxRequestsPerMinute int
	MaxFailedLogins     int
	BlockDuration       time.Duration
	TrustedIPs         []string
	BlockedUserAgents  []string
	IPHubAPIKey        string
}

// Default configuration suitable for non-profit organizations
var DefaultSecurityConfig = SecurityConfig{
	MaxRequestsPerMinute: 30,     // 1 request per 2 seconds average (gentler rate limit)
	MaxFailedLogins:     5,       // Block after 5 failed attempts
	BlockDuration:       15 * time.Minute,
	TrustedIPs: []string{
		"10.0.0.0/8",      // Internal network
		"172.16.0.0/12",   // VPN network
		"192.168.0.0/16",  // Local network
	},
	BlockedUserAgents: []string{
		"zgrab",
		"masscan",
		"nikto",
		"nmap",
		"sqlmap",
		"python-requests",
		"go-http-client",
		"curl",
		"wget",
	},
}

// RateLimiter tracks request rates per IP
type RateLimiter struct {
	requests    map[string][]time.Time
	mu          sync.RWMutex
	config      *SecurityConfig
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *SecurityConfig) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		config:   config,
	}
}

// AllowRequest checks if a request from an IP should be allowed
func (r *RateLimiter) AllowRequest(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	window := now.Add(-time.Minute)

	// Clean old requests
	if times, exists := r.requests[ip]; exists {
		newTimes := times[:0]
		for _, t := range times {
			if t.After(window) {
				newTimes = append(newTimes, t)
			}
		}
		r.requests[ip] = newTimes
	}

	// Check rate limit
	if len(r.requests[ip]) >= r.config.MaxRequestsPerMinute {
		return false
	}

	// Record new request
	r.requests[ip] = append(r.requests[ip], now)
	return true
}

// IPHubResponse represents the response from IPHub API
type IPHubResponse struct {
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode"`
	CountryName string `json:"countryName"`
	Block       int    `json:"block"`
	ISP         string `json:"isp"`
}

// IPHubClient handles IP geolocation and VPN detection
type IPHubClient struct {
	baseURL string
}

var (
	ipHubClientInstance *IPHubClient
	once               sync.Once
)

// NewIPHubClient creates a new IPHub client instance
func NewIPHubClient() *IPHubClient {
	return &IPHubClient{
		baseURL: "https://v3.iphub.info",
	}
}

// getIPHubClient returns a singleton instance of IPHubClient
func getIPHubClient() *IPHubClient {
	once.Do(func() {
		ipHubClientInstance = NewIPHubClient()
	})
	return ipHubClientInstance
}

// GetIPInfo retrieves information about an IP address
func (c *IPHubClient) GetIPInfo(ip string) (*IPHubResponse, error) {
	var response IPHubResponse
	
	request := http.NewRequest("https://v3.iphub.info/ip/" + ip, &http.RequestOptions{
		Method: "GET",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	})

	resp, err := http.Fetch(request)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP info: %w", err)
	}

	if !resp.Ok() {
		return nil, fmt.Errorf("IPHub API error: %s", resp.StatusText)
	}

	if err := resp.JSON(&response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &response, nil
}

// AuditRequest represents an incoming HTTP request for auditing
type AuditRequest struct {
	Method      string
	Path        string
	Headers     map[string]string
	RemoteAddr  string
	RequestID   string
	StartTime   time.Time
}

// AuditMiddleware creates audit logs for all API requests
func AuditMiddleware(auditService *audit.Service, rateLimiter *RateLimiter) func(req *AuditRequest) error {
	return func(req *AuditRequest) error {
		// Get client IP and country
		clientIP := getClientIP(req)
		country := getCountryFromIP(clientIP)
		
		// Check rate limit
		if !rateLimiter.AllowRequest(clientIP) {
			event := &audit.AuditEvent{
				Timestamp:    time.Now(),
				Action:       fmt.Sprintf("%s %s", req.Method, req.Path),
				Category:     getCategoryFromPath(req.Path),
				Status:       audit.StatusBlocked,
				Severity:     audit.SeverityWarn,
				ResourceType: "API",
				RequestID:    req.RequestID,
				IPAddress:    clientIP,
				UserAgent:    req.Headers["User-Agent"],
				Metadata: map[string]string{
					"reason":  "rate_limit_exceeded",
					"country": country,
				},
			}
			auditService.Log(event)
			console.Warn(fmt.Sprintf("Rate limit exceeded for IP %s (%s)", clientIP, country))
			return fmt.Errorf("rate limit exceeded")
		}

		// Record metrics
		duration := time.Since(req.StartTime)

		// Create audit event
		event := &audit.AuditEvent{
			Timestamp:    time.Now(),
			Action:       fmt.Sprintf("%s %s", req.Method, req.Path),
			Category:     getCategoryFromPath(req.Path),
			Status:       audit.StatusSuccess,
			Severity:     audit.SeverityInfo,
			ResourceType: "API",
			RequestID:    req.RequestID,
			IPAddress:    clientIP,
			UserAgent:    req.Headers["User-Agent"],
			Metadata: map[string]string{
				"method":      req.Method,
				"path":        req.Path,
				"duration_ms": fmt.Sprintf("%d", duration.Milliseconds()),
				"country":     country,
			},
		}
		auditService.Log(event)

		// Log request details
		console.Info(fmt.Sprintf(
			"Request completed: method=%s path=%s duration=%dms ip=%s country=%s",
			req.Method, req.Path, duration.Milliseconds(), clientIP, country,
		))

		return nil
	}
}

// Helper functions
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

func getCategoryFromPath(path string) string {
	switch {
	case strings.Contains(path, "/auth"):
		return audit.CategoryAuth
	case strings.Contains(path, "/user"):
		return audit.CategoryUser
	case strings.Contains(path, "/email"):
		return audit.CategoryEmail
	default:
		return audit.CategorySystem
	}
}

func getClientIP(req *AuditRequest) string {
	// Check X-Forwarded-For header
	if xff := req.Headers["X-Forwarded-For"]; xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	return strings.Split(req.RemoteAddr, ":")[0]
}

func getCountryFromIP(ip string) string {
	client := getIPHubClient()
	resp, err := client.GetIPInfo(ip)
	if err != nil {
		console.Error(fmt.Sprintf("Failed to get country for IP %s: %v", ip, err))
		return "UNKNOWN"
	}
	return resp.CountryCode
}
