package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config structure matching config.yaml
type Config struct {
	APIKeys struct {
		Cloudflare   string `yaml:"cloudflare"`
		VirusTotal   string `yaml:"virustotal"`
		AWSAccessKey string `yaml:"aws_access_key"`  // Added for Route53
		AWSSecretKey string `yaml:"aws_secret_key"`  // Added for Route53
		DigitalOcean string `yaml:"digitalocean"`    // Added for DigitalOcean
	} `yaml:"api_keys"`

	Endpoints struct {
		Cloudflare   string `yaml:"cloudflare"`
		VirusTotal   string `yaml:"virustotal"`
		AWSEndpoint  string `yaml:"aws_endpoint"`    // Added for AWS
		DOEndpoint   string `yaml:"digitalocean_endpoint"` // Added for DigitalOcean
	} `yaml:"endpoints"`

	Monitoring struct {
		IntervalSeconds int `yaml:"interval_seconds"`
		MaxRetries      int `yaml:"max_retries"`
		TimeoutSeconds  int `yaml:"timeout_seconds"`
		AlertThreshold  int `yaml:"alert_threshold"`
	} `yaml:"monitoring"`

	Cloudflare struct {
		APIKey string   `yaml:"api_key"`
		Zones  []string `yaml:"zones"`
	} `yaml:"cloudflare"`

	AWS struct {
		Region       string   `yaml:"region"`
		Route53Zones []string `yaml:"route53_zones"` // Added for Route53
	} `yaml:"aws"` // Added for AWS configuration

	DigitalOcean struct {
		Domains []string `yaml:"domains"` // Added for DigitalOcean
	} `yaml:"digitalocean"` // Added for DigitalOcean configuration

	Logging struct {
		Level  string `yaml:"level"`
		Output string `yaml:"output"`
	} `yaml:"logging"`
}

// LoadConfig reads the YAML configuration from the given path
func LoadConfig(path string) (*Config, error) {
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	// Decode YAML
	cfg := &Config{}
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config YAML: %v", err)
	}

	// Set default values if not specified
	if cfg.Monitoring.IntervalSeconds == 0 {
		cfg.Monitoring.IntervalSeconds = 60 // Default to 60 seconds
	}

	if cfg.Monitoring.TimeoutSeconds == 0 {
		cfg.Monitoring.TimeoutSeconds = 30 // Default to 30 seconds
	}

	if cfg.Monitoring.AlertThreshold == 0 {
		cfg.Monitoring.AlertThreshold = 5 // Default to 5 detections
	}

	if cfg.Endpoints.Cloudflare == "" {
		cfg.Endpoints.Cloudflare = "https://api.cloudflare.com/client/v4/" // Default Cloudflare endpoint
	}

	if cfg.Endpoints.VirusTotal == "" {
		cfg.Endpoints.VirusTotal = "https://www.virustotal.com/api/v3/" // Default VirusTotal endpoint
	}

	if cfg.Endpoints.AWSEndpoint == "" {
		cfg.Endpoints.AWSEndpoint = "https://route53.amazonaws.com/" // Default AWS endpoint
	}

	if cfg.Endpoints.DOEndpoint == "" {
		cfg.Endpoints.DOEndpoint = "https://api.digitalocean.com/v2/" // Default DigitalOcean endpoint
	}

	if cfg.AWS.Region == "" {
		cfg.AWS.Region = "us-east-1" // Default AWS region
	}

	return cfg, nil
}

// ValidateConfig validates the configuration for required fields
func (c *Config) ValidateConfig() error {
	// Check if at least one provider is configured
	hasCloudflare := c.APIKeys.Cloudflare != "" && len(c.Cloudflare.Zones) > 0
	hasAWS := c.APIKeys.AWSAccessKey != "" && c.APIKeys.AWSSecretKey != "" && len(c.AWS.Route53Zones) > 0
	hasDigitalOcean := c.APIKeys.DigitalOcean != "" && len(c.DigitalOcean.Domains) > 0

	if !hasCloudflare && !hasAWS && !hasDigitalOcean {
		return fmt.Errorf("no DNS providers configured. Please configure at least one provider")
	}

	// Validate Cloudflare configuration if enabled
	if hasCloudflare {
		if c.APIKeys.Cloudflare == "" {
			return fmt.Errorf("Cloudflare API key is required when Cloudflare zones are configured")
		}
		for i, zone := range c.Cloudflare.Zones {
			if zone == "" {
				return fmt.Errorf("Cloudflare zone #%d cannot be empty", i+1)
			}
		}
	}

	// Validate AWS configuration if enabled
	if hasAWS {
		if c.APIKeys.AWSAccessKey == "" {
			return fmt.Errorf("AWS access key is required when AWS Route53 zones are configured")
		}
		if c.APIKeys.AWSSecretKey == "" {
			return fmt.Errorf("AWS secret key is required when AWS Route53 zones are configured")
		}
		if c.AWS.Region == "" {
			return fmt.Errorf("AWS region is required when AWS is configured")
		}
		for i, zone := range c.AWS.Route53Zones {
			if zone == "" {
				return fmt.Errorf("AWS Route53 zone #%d cannot be empty", i+1)
			}
		}
	}

	// Validate DigitalOcean configuration if enabled
	if hasDigitalOcean {
		if c.APIKeys.DigitalOcean == "" {
			return fmt.Errorf("DigitalOcean API key is required when DigitalOcean domains are configured")
		}
		for i, domain := range c.DigitalOcean.Domains {
			if domain == "" {
				return fmt.Errorf("DigitalOcean domain #%d cannot be empty", i+1)
			}
		}
	}

	// Validate monitoring settings
	if c.Monitoring.IntervalSeconds < 30 {
		return fmt.Errorf("monitoring interval must be at least 30 seconds")
	}

	if c.Monitoring.TimeoutSeconds < 10 {
		return fmt.Errorf("timeout must be at least 10 seconds")
	}

	if c.Monitoring.AlertThreshold < 1 {
		return fmt.Errorf("alert threshold must be at least 1")
	}

	return nil
}

// GetProviderZones returns the zones/domains for a specific provider
func (c *Config) GetProviderZones(providerName string) []string {
	switch providerName {
	case "Cloudflare":
		return c.Cloudflare.Zones
	case "AWS Route53":
		return c.AWS.Route53Zones
	case "DigitalOcean":
		return c.DigitalOcean.Domains
	default:
		return []string{}
	}
}

// HasCloudflare returns true if Cloudflare is configured
func (c *Config) HasCloudflare() bool {
	return c.APIKeys.Cloudflare != "" && len(c.Cloudflare.Zones) > 0
}

// HasAWS returns true if AWS Route53 is configured
func (c *Config) HasAWS() bool {
	return c.APIKeys.AWSAccessKey != "" && c.APIKeys.AWSSecretKey != "" && len(c.AWS.Route53Zones) > 0
}

// HasDigitalOcean returns true if DigitalOcean is configured
func (c *Config) HasDigitalOcean() bool {
	return c.APIKeys.DigitalOcean != "" && len(c.DigitalOcean.Domains) > 0
}

// GetEnabledProviders returns a list of enabled DNS providers
func (c *Config) GetEnabledProviders() []string {
	providers := []string{}

	if c.HasCloudflare() {
		providers = append(providers, "Cloudflare")
	}

	if c.HasAWS() {
		providers = append(providers, "AWS Route53")
	}

	if c.HasDigitalOcean() {
		providers = append(providers, "DigitalOcean")
	}

	return providers
}

// GetProviderCount returns the number of configured DNS providers
func (c *Config) GetProviderCount() int {
	count := 0

	if c.HasCloudflare() {
		count++
	}

	if c.HasAWS() {
		count++
	}

	if c.HasDigitalOcean() {
		count++
	}

	return count
}

