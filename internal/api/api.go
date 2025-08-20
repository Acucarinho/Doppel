package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"doppel/internal/config"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
)

// DNSProvider interface defines the contract for all DNS providers
type DNSProvider interface {
	GetDNSLogs(zone string) ([]string, error)
	ProviderName() string
}

// CloudflareClient handles interactions with Cloudflare's API
type CloudflareClient struct {
	APIKey     string
	Endpoint   string
	HTTPClient *http.Client
}

// Route53Client handles interactions with AWS Route53's query logs via CloudWatch
type Route53Client struct {
	AccessKey    string
	SecretKey    string
	Region       string
	Session      *session.Session
	CloudWatchClient *cloudwatchlogs.CloudWatchLogs
}

// CloudWatchConfig holds CloudWatch specific configuration
type CloudWatchConfig struct {
	LogGroupName  string
	LogStreamName string
	Query         string
	StartTime     time.Time
	EndTime       time.Time
}

// NewCloudflareClient initializes a new Cloudflare API client
func NewCloudflareClient(cfg *config.Config) *CloudflareClient {
	return &CloudflareClient{
		APIKey:   cfg.APIKeys.Cloudflare,
		Endpoint: cfg.Endpoints.Cloudflare,
		HTTPClient: &http.Client{
			Timeout: time.Duration(cfg.Monitoring.TimeoutSeconds) * time.Second,
		},
	}
}

// NewRoute53Client initializes a new AWS Route53 API client with CloudWatch integration
func NewRoute53Client(cfg *config.Config) (*Route53Client, error) {
	// Create AWS session
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(cfg.AWS.Region),
		Credentials: credentials.NewStaticCredentials(
			cfg.APIKeys.AWSAccessKey,
			cfg.APIKeys.AWSSecretKey,
			"", // token (optional)
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

	// Create CloudWatch Logs client
	cwClient := cloudwatchlogs.New(sess)

	return &Route53Client{
		AccessKey:       cfg.APIKeys.AWSAccessKey,
		SecretKey:       cfg.APIKeys.AWSSecretKey,
		Region:          cfg.AWS.Region,
		Session:         sess,
		CloudWatchClient: cwClient,
	}, nil
}

// ProviderName returns the name of the Cloudflare provider
func (c *CloudflareClient) ProviderName() string {
	return "Cloudflare"
}

// ProviderName returns the name of the AWS Route53 provider
func (r *Route53Client) ProviderName() string {
	return "AWS Route53"
}

// GetDNSLogs fetches DNS query logs from Cloudflare
func (c *CloudflareClient) GetDNSLogs(zoneID string) ([]string, error) {
	url := fmt.Sprintf("%szones/%s/dns_analytics/report", c.Endpoint, zoneID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if err := validateAPIResponse(resp); err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API validation failed: %v, response: %s", err, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

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
		Success  bool     `json:"success"`
		Errors   []string `json:"errors"`
		Messages []string `json:"messages"`
	}

	err = json.Unmarshal(body, &analyticsResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	if !analyticsResponse.Success {
		errorMsg := "Cloudflare API reported failure"
		if len(analyticsResponse.Errors) > 0 {
			errorMsg += fmt.Sprintf(": %v", analyticsResponse.Errors)
		}
		return nil, fmt.Errorf(errorMsg)
	}

	var logs []string
	for _, entry := range analyticsResponse.Result.Data {
		logEntry := fmt.Sprintf("%s %s query for %s from %s (count: %d)",
			entry.Timestamp, entry.QueryType, entry.QueryName, entry.ClientIP, entry.Count)
		logs = append(logs, logEntry)
	}

	return logs, nil
}

// GetDNSLogs fetches DNS query logs from AWS Route53 via CloudWatch Logs
func (r *Route53Client) GetDNSLogs(hostedZoneID string) ([]string, error) {
	// Default CloudWatch log group name for Route53 query logging
	logGroupName := fmt.Sprintf("/aws/route53/%s", hostedZoneID)
	
	// Check if log group exists
	_, err := r.CloudWatchClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(logGroupName),
	})
	if err != nil {
		return nil, fmt.Errorf("CloudWatch log group not found for zone %s: %v", hostedZoneID, err)
	}

	// Set time range for query (last 5 minutes)
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute)

	// Query CloudWatch Logs for Route53 DNS queries
	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:  aws.String(logGroupName),
		StartTime:     aws.Int64(startTime.Unix() * 1000), // CloudWatch uses milliseconds
		EndTime:       aws.Int64(endTime.Unix() * 1000),
		FilterPattern: aws.String(`[version, account_id, hosted_zone_id, query_name, query_type]`),
	}

	result, err := r.CloudWatchClient.FilterLogEvents(input)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CloudWatch logs for zone %s: %v", hostedZoneID, err)
	}

	var logs []string
	for _, event := range result.Events {
		if event.Message != nil {
			// Parse Route53 query log format
			parsedLog, err := parseRoute53QueryLog(*event.Message, hostedZoneID)
			if err != nil {
				fmt.Printf("[WARNING] Failed to parse Route53 log entry: %v\n", err)
				continue
			}
			logs = append(logs, parsedLog)
		}
	}

	if len(logs) == 0 {
		fmt.Printf("[INFO] No DNS query logs found in CloudWatch for zone %s (time range: %s to %s)\n",
			hostedZoneID, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	}

	return logs, nil
}

// parseRoute53QueryLog parses Route53 query log entries
// Format: version account_id hosted_zone_id query_name query_type ...
func parseRoute53QueryLog(logEntry, hostedZoneID string) (string, error) {
	// Example Route53 query log format:
	// "1.0 123456789012 Z123456789ABCD example.com A 192.168.1.100 2023-01-01T00:00:00Z"
	
	var (
		version      string
		accountID    string
		zoneID       string
		queryName    string
		queryType    string
		sourceIP     string
		timestamp    string
	)

	// Simple parsing - adjust based on your actual log format
	_, err := fmt.Sscanf(logEntry, "%s %s %s %s %s %s %s",
		&version, &accountID, &zoneID, &queryName, &queryType, &sourceIP, &timestamp)
	if err != nil {
		// Try alternative format without sourceIP and timestamp
		_, err = fmt.Sscanf(logEntry, "%s %s %s %s %s",
			&version, &accountID, &zoneID, &queryName, &queryType)
		if err != nil {
			return "", fmt.Errorf("failed to parse Route53 log format: %v", err)
		}
		// Use current time if timestamp not available
		timestamp = time.Now().Format(time.RFC3339)
		sourceIP = "unknown"
	}

	logMessage := fmt.Sprintf("%s %s query for %s from %s (zone: %s)",
		timestamp, queryType, queryName, sourceIP, hostedZoneID)

	return logMessage, nil
}

// GetQueryLogsWithCustomConfig allows custom CloudWatch query configuration
func (r *Route53Client) GetQueryLogsWithCustomConfig(config CloudWatchConfig) ([]string, error) {
	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:  aws.String(config.LogGroupName),
		StartTime:     aws.Int64(config.StartTime.Unix() * 1000),
		EndTime:       aws.Int64(config.EndTime.Unix() * 1000),
	}

	if config.Query != "" {
		input.FilterPattern = aws.String(config.Query)
	}

	if config.LogStreamName != "" {
		input.LogStreamNames = []*string{aws.String(config.LogStreamName)}
	}

	result, err := r.CloudWatchClient.FilterLogEvents(input)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CloudWatch logs: %v", err)
	}

	var logs []string
	for _, event := range result.Events {
		if event.Message != nil {
			logs = append(logs, *event.Message)
		}
	}

	return logs, nil
}

// ListLogGroups lists available CloudWatch log groups for Route53
func (r *Route53Client) ListLogGroups() ([]string, error) {
	result, err := r.CloudWatchClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String("/aws/route53/"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list log groups: %v", err)
	}

	var logGroups []string
	for _, group := range result.LogGroups {
		if group.LogGroupName != nil {
			logGroups = append(logGroups, *group.LogGroupName)
		}
	}

	return logGroups, nil
}

// CheckDNSLogs is a convenience wrapper for Cloudflare
func (c *CloudflareClient) CheckDNSLogs(zoneID string) error {
	logs, err := c.GetDNSLogs(zoneID)
	if err != nil {
		return fmt.Errorf("failed to check DNS logs for zone %s: %v", zoneID, err)
	}

	fmt.Printf("[INFO] Retrieved %d DNS log entries from zone %s\n", len(logs), zoneID)
	return nil
}

// CheckDNSLogs is a convenience wrapper for Route53
func (r *Route53Client) CheckDNSLogs(hostedZoneID string) error {
	logs, err := r.GetDNSLogs(hostedZoneID)
	if err != nil {
		return fmt.Errorf("failed to check DNS logs for zone %s: %v", hostedZoneID, err)
	}

	fmt.Printf("[INFO] Retrieved %d DNS log entries from zone %s\n", len(logs), hostedZoneID)
	return nil
}

// GetZoneAnalytics retrieves comprehensive zone analytics for Cloudflare
func (c *CloudflareClient) GetZoneAnalytics(zoneID string, since time.Time, until time.Time) (map[string]interface{}, error) {
	if until.IsZero() {
		until = time.Now()
	}

	url := fmt.Sprintf("%szones/%s/analytics/dashboard", c.Endpoint, zoneID)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	q := req.URL.Query()
	q.Add("since", since.Format(time.RFC3339))
	q.Add("until", until.Format(time.RFC3339))
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+c.APIKey)
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

// GetRecentZoneAnalytics retrieves recent analytics for Cloudflare
func (c *CloudflareClient) GetRecentZoneAnalytics(zoneID string, duration time.Duration) (map[string]interface{}, error) {
	since := time.Now().Add(-duration)
	return c.GetZoneAnalytics(zoneID, since, time.Time{})
}

// VirusTotalClient handles threat intelligence
type VirusTotalClient struct {
	APIKey     string
	Endpoint   string
	HTTPClient *http.Client
}

// NewVirusTotalClient initializes VirusTotal client
func NewVirusTotalClient(cfg *config.Config) *VirusTotalClient {
	client := &VirusTotalClient{
		APIKey:   cfg.APIKeys.VirusTotal,
		Endpoint: cfg.Endpoints.VirusTotal,
		HTTPClient: &http.Client{
			Timeout: time.Duration(cfg.Monitoring.TimeoutSeconds) * time.Second,
		},
	}

	if client.APIKey == "" {
		fmt.Println("[WARNING] VirusTotal API key not configured. Reputation checking will be disabled.")
	}

	return client
}

// ScanIP queries VirusTotal for IP reputation
func (v *VirusTotalClient) ScanIP(ip string) (map[string]interface{}, error) {
	if v.APIKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not configured")
	}

	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}

	url := fmt.Sprintf("%s/ip_addresses/%s", v.Endpoint, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("x-apikey", v.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if err := validateAPIResponse(resp); err != nil {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API response validation failed: %v, response: %s", err, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	return result, nil
}

// CheckIPReputation provides simplified IP reputation checking
func (v *VirusTotalClient) CheckIPReputation(ip string) (bool, error) {
	result, err := v.ScanIP(ip)
	if err != nil {
		return false, err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("invalid response format: missing data field")
	}

	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("invalid response format: missing attributes field")
	}

	reputation, ok := attributes["reputation"].(float64)
	if !ok {
		if stats, ok := attributes["last_analysis_stats"].(map[string]interface{}); ok {
			if malicious, ok := stats["malicious"].(float64); ok && malicious > 0 {
				return false, nil
			}
			return true, nil
		}
		return false, fmt.Errorf("reputation score not found in response")
	}

	return reputation >= 0, nil
}

// BatchScanIP allows scanning multiple IPs
func (v *VirusTotalClient) BatchScanIP(ips []string) (map[string]bool, error) {
	results := make(map[string]bool)

	for _, ip := range ips {
		isClean, err := v.CheckIPReputation(ip)
		if err != nil {
			fmt.Printf("[WARNING] Failed to check IP %s: %v\n", ip, err)
			results[ip] = false
			continue
		}
		results[ip] = isClean
	}

	return results, nil
}

// GetIPReport retrieves full IP analysis report
func (v *VirusTotalClient) GetIPReport(ip string) (map[string]interface{}, error) {
	result, err := v.ScanIP(ip)
	if err != nil {
		return nil, err
	}

	report := make(map[string]interface{})
	if data, ok := result["data"].(map[string]interface{}); ok {
		if id, ok := data["id"].(string); ok {
			report["id"] = id
		}
		if typeStr, ok := data["type"].(string); ok {
			report["type"] = typeStr
		}

		if attributes, ok := data["attributes"].(map[string]interface{}); ok {
			report["reputation"] = attributes["reputation"]
			report["last_analysis_stats"] = attributes["last_analysis_stats"]
			report["asn"] = attributes["asn"]
			report["country"] = attributes["country"]
		}
	}

	return report, nil
}

// validateAPIResponse checks HTTP response for errors
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

// IsAPIEnabled checks if VirusTotal API is configured
func (v *VirusTotalClient) IsAPIEnabled() bool {
	return v.APIKey != ""
}

// GetRateLimitInfo extracts rate limit information
func GetRateLimitInfo(resp *http.Response) map[string]string {
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
