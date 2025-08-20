package cloudflare

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"doppel/internal/config"
)

// CloudflareClient implements DNSProvider for Cloudflare
type CloudflareClient struct {
	cfg        *config.Config
	HTTPClient *http.Client
}

// NewCloudflareClient creates a new Cloudflare API client
func NewCloudflareClient(cfg *config.Config) *CloudflareClient {
	return &CloudflareClient{
		cfg: cfg,
		HTTPClient: &http.Client{
			Timeout: time.Duration(cfg.Monitoring.TimeoutSeconds) * time.Second,
		},
	}
}

// ProviderName returns the name of the provider
func (c *CloudflareClient) ProviderName() string {
	return "Cloudflare"
}

// GetDNSLogs fetches DNS query logs from Cloudflare
func (c *CloudflareClient) GetDNSLogs(zoneID string) ([]string, error) {
	if c.cfg.APIKeys.Cloudflare == "" {
		return nil, fmt.Errorf("Cloudflare API key not configured")
	}

	if c.cfg.Endpoints.Cloudflare == "" {
		return nil, fmt.Errorf("Cloudflare endpoint not configured")
	}

	url := fmt.Sprintf("%szones/%s/dns_analytics/report", c.cfg.Endpoints.Cloudflare, zoneID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Set required headers for Cloudflare API
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKeys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")
	// Removed X-Auth-Email header since it's not in the config

	// Execute the request with timeout
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Validate API response
	if err := validateAPIResponse(resp); err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API validation failed: %v, response: %s", err, string(body))
	}

	// Read and parse response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse Cloudflare DNS analytics response
	var analyticsResponse struct {
		Result struct {
			Data []struct {
				Timestamp string `json:"timestamp"`
				QueryType string `json:"query_type"`
				QueryName string `json:"name"`
				ClientIP  string `json:"client_ip"`
				Count     int    `json:"count"`
			} `json:"data"`
		} `json:"result"`
		Success  bool           `json:"success"`
		Errors   []cloudflareError `json:"errors"`
		Messages []string       `json:"messages"`
	}

	err = json.Unmarshal(body, &analyticsResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	// Check for API-level errors
	if !analyticsResponse.Success {
		errorMsg := "Cloudflare API reported failure"
		if len(analyticsResponse.Errors) > 0 {
			errorMsg += fmt.Sprintf(": %v", analyticsResponse.Errors)
		}
		return nil, fmt.Errorf(errorMsg)
	}

	// Convert structured data to log format strings
	var logs []string
	for _, entry := range analyticsResponse.Result.Data {
		logEntry := fmt.Sprintf("%s %s query for %s from %s (count: %d)",
			entry.Timestamp, entry.QueryType, entry.QueryName, entry.ClientIP, entry.Count)
		logs = append(logs, logEntry)
	}

	return logs, nil
}

// CheckDNSLogs is a convenience wrapper for GetDNSLogs
func (c *CloudflareClient) CheckDNSLogs(zoneID string) error {
	logs, err := c.GetDNSLogs(zoneID)
	if err != nil {
		return fmt.Errorf("failed to check DNS logs for zone %s: %v", zoneID, err)
	}

	fmt.Printf("[INFO] Retrieved %d DNS log entries from zone %s\n", len(logs), zoneID)
	return nil
}

// GetZoneAnalytics retrieves comprehensive zone analytics
func (c *CloudflareClient) GetZoneAnalytics(zoneID string, since time.Time, until time.Time) (map[string]interface{}, error) {
	if until.IsZero() {
		until = time.Now()
	}

	url := fmt.Sprintf("%szones/%s/analytics/dashboard", c.cfg.Endpoints.Cloudflare, zoneID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add time range parameters
	q := req.URL.Query()
	q.Add("since", since.Format(time.RFC3339))
	q.Add("until", until.Format(time.RFC3339))
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKeys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if err := validateAPIResponse(resp); err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	return result, nil
}

// GetRecentZoneAnalytics retrieves analytics for the last specified duration
func (c *CloudflareClient) GetRecentZoneAnalytics(zoneID string, duration time.Duration) (map[string]interface{}, error) {
	since := time.Now().Add(-duration)
	return c.GetZoneAnalytics(zoneID, since, time.Time{})
}

// TestConnection tests the Cloudflare API connection
func (c *CloudflareClient) TestConnection() error {
	if c.cfg.APIKeys.Cloudflare == "" {
		return fmt.Errorf("Cloudflare API key not configured")
	}

	// Simple API call to verify connectivity
	url := fmt.Sprintf("%szones", c.cfg.Endpoints.Cloudflare)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKeys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("test request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("test failed with status: %d", resp.StatusCode)
	}

	return nil
}

// GetZoneInfo retrieves basic information about a zone
func (c *CloudflareClient) GetZoneInfo(zoneID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%szones/%s", c.cfg.Endpoints.Cloudflare, zoneID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKeys.Cloudflare)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if err := validateAPIResponse(resp); err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	return result, nil
}

// Helper types for Cloudflare API responses
type cloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// validateAPIResponse checks HTTP response for common API errors
func validateAPIResponse(resp *http.Response) error {
	if resp.StatusCode >= 400 {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("API authentication failed (401)")
		case http.StatusForbidden:
			return fmt.Errorf("API access forbidden (403)")
		case http.StatusTooManyRequests:
			return fmt.Errorf("API rate limit exceeded (429)")
		default:
			return fmt.Errorf("API returned error status: %d", resp.StatusCode)
		}
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		return fmt.Errorf("unexpected content type: %s", contentType)
	}

	return nil
}

// GetRateLimitInfo extracts rate limit information from response headers
func (c *CloudflareClient) GetRateLimitInfo(resp *http.Response) map[string]string {
	limits := make(map[string]string)
	
	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"X-RateLimit-Reset",
	}
	
	for _, header := range rateLimitHeaders {
		if value := resp.Header.Get(header); value != "" {
			limits[header] = value
		}
	}
	
	return limits
}

// IsConfigured checks if Cloudflare is properly configured
func (c *CloudflareClient) IsConfigured() bool {
	return c.cfg.APIKeys.Cloudflare != "" && c.cfg.Endpoints.Cloudflare != ""
}

// GetZones returns the list of configured Cloudflare zones
func (c *CloudflareClient) GetZones() []string {
	return c.cfg.Cloudflare.Zones
}