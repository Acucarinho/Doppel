package route53

import (
	"fmt"
	"time"

	"doppel/internal/config"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/route53resolver"
)

// Route53Client implements DNSProvider for AWS Route53
type Route53Client struct {
	cfg               *config.Config
	session           *session.Session
	resolverClient    *route53resolver.Route53Resolver
	cloudwatchClient  *cloudwatchlogs.CloudWatchLogs
}

// NewRoute53Client creates a new AWS Route53 API client
func NewRoute53Client(cfg *config.Config) (*Route53Client, error) {
	if cfg.APIKeys.AWSAccessKey == "" || cfg.APIKeys.AWSSecretKey == "" {
		return nil, fmt.Errorf("AWS credentials not configured")
	}

	if cfg.AWS.Region == "" {
		return nil, fmt.Errorf("AWS region not configured")
	}

	// Create AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(cfg.AWS.Region),
		Credentials: credentials.NewStaticCredentials(
			cfg.APIKeys.AWSAccessKey,
			cfg.APIKeys.AWSSecretKey,
			"", // token (optional)
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

	return &Route53Client{
		cfg:              cfg,
		session:          sess,
		resolverClient:   route53resolver.New(sess),
		cloudwatchClient: cloudwatchlogs.New(sess),
	}, nil
}

// ProviderName returns the name of the provider
func (r *Route53Client) ProviderName() string {
	return "AWS Route53"
}

// GetDNSLogs fetches DNS query logs from AWS Route53 Resolver
func (r *Route53Client) GetDNSLogs(hostedZoneID string) ([]string, error) {
	// Try to get logs from Route53 Resolver Query Logging first
	resolverLogs, err := r.getResolverQueryLogs(hostedZoneID)
	if err == nil && len(resolverLogs) > 0 {
		return resolverLogs, nil
	}

	// Fallback to CloudWatch Logs (traditional Route53 query logging)
	cloudwatchLogs, err := r.getCloudWatchLogs(hostedZoneID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS logs from both Resolver and CloudWatch: %v", err)
	}

	return cloudwatchLogs, nil
}

// getResolverQueryLogs fetches logs from Route53 Resolver Query Logging
func (r *Route53Client) getResolverQueryLogs(hostedZoneID string) ([]string, error) {
	// List resolver query log configurations
	listInput := &route53resolver.ListResolverQueryLogConfigsInput{
		MaxResults: aws.Int64(50),
	}

	result, err := r.resolverClient.ListResolverQueryLogConfigs(listInput)
	if err != nil {
		return nil, fmt.Errorf("failed to list resolver query log configs: %v", err)
	}

	var logs []string

	// Check each configuration for our hosted zone
	for _, config := range result.ResolverQueryLogConfigs {
		if config.DestinationArn == nil || config.Id == nil {
			continue
		}

		// Get query logs for this configuration
		queryInput := &route53resolver.ListResolverQueryLogConfigAssociationsInput{
			Filters: []*route53resolver.Filter{
				{
					Name:   aws.String("ResolverQueryLogConfigId"),
					Values: []*string{config.Id},
				},
			},
			MaxResults: aws.Int64(100),
		}

		associations, err := r.resolverClient.ListResolverQueryLogConfigAssociations(queryInput)
		if err != nil {
			continue
		}

		for _, association := range associations.ResolverQueryLogConfigAssociations {
			if association.ResourceId != nil && *association.ResourceId == hostedZoneID {
				// Found our hosted zone, get recent queries
				recentQueries, err := r.getRecentResolverQueries(*config.DestinationArn)
				if err != nil {
					return nil, err
				}
				logs = append(logs, recentQueries...)
			}
		}
	}

	return logs, nil
}

// getRecentResolverQueries gets recent queries from CloudWatch Logs for Resolver
func (r *Route53Client) getRecentResolverQueries(logGroupArn string) ([]string, error) {
	// Extract log group name from ARN
	logGroupName := extractLogGroupNameFromArn(logGroupArn)
	if logGroupName == "" {
		return nil, fmt.Errorf("invalid log group ARN: %s", logGroupArn)
	}

	// Query CloudWatch Logs for recent resolver queries
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute) // Last 5 minutes

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:  aws.String(logGroupName),
		StartTime:     aws.Int64(startTime.Unix() * 1000),
		EndTime:       aws.Int64(endTime.Unix() * 1000),
		FilterPattern: aws.String(`[version, account_id, region, vpc_id, query_name, query_type]`),
	}

	result, err := r.cloudwatchClient.FilterLogEvents(input)
	if err != nil {
		return nil, fmt.Errorf("failed to filter CloudWatch logs: %v", err)
	}

	var logs []string
	for _, event := range result.Events {
		if event.Message != nil {
			parsedLog, err := parseResolverQueryLog(*event.Message)
			if err != nil {
				continue // Skip unparseable logs
			}
			logs = append(logs, parsedLog)
		}
	}

	return logs, nil
}

// getCloudWatchLogs fetches traditional Route53 query logs from CloudWatch
func (r *Route53Client) getCloudWatchLogs(hostedZoneID string) ([]string, error) {
	logGroupName := fmt.Sprintf("/aws/route53/%s", hostedZoneID)

	// Check if log group exists
	_, err := r.cloudwatchClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(logGroupName),
	})
	if err != nil {
		return nil, fmt.Errorf("CloudWatch log group not found for zone %s: %v", hostedZoneID, err)
	}

	// Set time range for query (last 5 minutes)
	endTime := time.Now()
	startTime := endTime.Add(-5 * time.Minute)

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:  aws.String(logGroupName),
		StartTime:     aws.Int64(startTime.Unix() * 1000),
		EndTime:       aws.Int64(endTime.Unix() * 1000),
		FilterPattern: aws.String(`[version, account_id, hosted_zone_id, query_name, query_type]`),
	}

	result, err := r.cloudwatchClient.FilterLogEvents(input)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CloudWatch logs for zone %s: %v", hostedZoneID, err)
	}

	var logs []string
	for _, event := range result.Events {
		if event.Message != nil {
			parsedLog, err := parseRoute53QueryLog(*event.Message, hostedZoneID)
			if err != nil {
				continue // Skip unparseable logs
			}
			logs = append(logs, parsedLog)
		}
	}

	if len(logs) == 0 {
		return nil, fmt.Errorf("no DNS query logs found for zone %s", hostedZoneID)
	}

	return logs, nil
}

// parseResolverQueryLog parses Route53 Resolver query log entries
func parseResolverQueryLog(logEntry string) (string, error) {
	// Example Resolver log format:
	// "1.0 account_id region vpc_id query_name query_type timestamp"
	var (
		version   string
		accountID string
		region    string
		vpcID     string
		queryName string
		queryType string
		timestamp string
	)

	_, err := fmt.Sscanf(logEntry, "%s %s %s %s %s %s %s",
		&version, &accountID, &region, &vpcID, &queryName, &queryType, &timestamp)
	if err != nil {
		return "", fmt.Errorf("failed to parse resolver log: %v", err)
	}

	return fmt.Sprintf("%s %s query for %s from VPC %s (region: %s)",
		timestamp, queryType, queryName, vpcID, region), nil
}

// parseRoute53QueryLog parses traditional Route53 query log entries
func parseRoute53QueryLog(logEntry, hostedZoneID string) (string, error) {
	// Example Route53 query log format:
	// "1.0 account_id hosted_zone_id query_name query_type source_ip timestamp"
	var (
		version   string
		accountID string
		zoneID    string
		queryName string
		queryType string
		sourceIP  string
		timestamp string
	)

	_, err := fmt.Sscanf(logEntry, "%s %s %s %s %s %s %s",
		&version, &accountID, &zoneID, &queryName, &queryType, &sourceIP, &timestamp)
	if err != nil {
		return "", fmt.Errorf("failed to parse Route53 log: %v", err)
	}

	return fmt.Sprintf("%s %s query for %s from %s (zone: %s)",
		timestamp, queryType, queryName, sourceIP, hostedZoneID), nil
}

// extractLogGroupNameFromArn extracts log group name from CloudWatch ARN
func extractLogGroupNameFromArn(arn string) string {
	// ARN format: arn:aws:logs:region:account-id:log-group:log-group-name:*
	for i := len(arn) - 1; i >= 0; i-- {
		if arn[i] == ':' {
			return arn[i+1:]
		}
	}
	return ""
}

// TestConnection tests the AWS API connection
func (r *Route53Client) TestConnection() error {
	// Test Route53 Resolver connection
	_, err := r.resolverClient.ListResolverQueryLogConfigs(&route53resolver.ListResolverQueryLogConfigsInput{
		MaxResults: aws.Int64(1),
	})
	if err != nil {
		return fmt.Errorf("Route53 Resolver connection test failed: %v", err)
	}

	// Test CloudWatch Logs connection
	_, err = r.cloudwatchClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		Limit: aws.Int64(1),
	})
	if err != nil {
		return fmt.Errorf("CloudWatch Logs connection test failed: %v", err)
	}

	return nil
}

// ListQueryLogConfigs lists all resolver query log configurations
func (r *Route53Client) ListQueryLogConfigs() ([]string, error) {
	input := &route53resolver.ListResolverQueryLogConfigsInput{
		MaxResults: aws.Int64(100),
	}

	result, err := r.resolverClient.ListResolverQueryLogConfigs(input)
	if err != nil {
		return nil, fmt.Errorf("failed to list query log configs: %v", err)
	}

	var configs []string
	for _, config := range result.ResolverQueryLogConfigs {
		if config.Name != nil && config.Id != nil {
			configs = append(configs, fmt.Sprintf("%s (%s)", *config.Name, *config.Id))
		}
	}

	return configs, nil
}

// GetHostedZoneInfo gets information about a Route53 hosted zone
func (r *Route53Client) GetHostedZoneInfo(hostedZoneID string) (map[string]interface{}, error) {
	// Note: This would require route53.New() client, but we're focusing on query logs
	// For now, return basic info
	info := map[string]interface{}{
		"hosted_zone_id": hostedZoneID,
		"provider":       "Route53",
		"has_logging":    len(r.cfg.AWS.Route53Zones) > 0,
	}

	return info, nil
}

// IsConfigured checks if Route53 is properly configured
func (r *Route53Client) IsConfigured() bool {
	return r.cfg.APIKeys.AWSAccessKey != "" &&
		r.cfg.APIKeys.AWSSecretKey != "" &&
		r.cfg.AWS.Region != "" &&
		len(r.cfg.AWS.Route53Zones) > 0
}

// GetZones returns the list of configured Route53 zones
func (r *Route53Client) GetZones() []string {
	return r.cfg.AWS.Route53Zones
}

// GetCloudWatchLogGroups lists CloudWatch log groups for Route53
func (r *Route53Client) GetCloudWatchLogGroups() ([]string, error) {
	result, err := r.cloudwatchClient.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
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