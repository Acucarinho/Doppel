package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// =====================
// Modelos de Config
// =====================

// Config structure matching config.yaml
type Config struct {
	APIKeys struct {
		AWSAccessKey string `yaml:"aws_access_key"`
		AWSSecretKey string `yaml:"aws_secret_key"`
	} `yaml:"api_keys"`

	Endpoints struct {
		AWSEndpoint string `yaml:"aws_endpoint"`
	} `yaml:"endpoints"`

	Monitoring struct {
		IntervalSeconds int `yaml:"interval_seconds"`
		MaxRetries      int `yaml:"max_retries"`
		TimeoutSeconds  int `yaml:"timeout_seconds"`
		AlertThreshold  int `yaml:"alert_threshold"`
	} `yaml:"monitoring"`

	AWS struct {
		Region       string   `yaml:"region"`
		Route53Zones []string `yaml:"route53_zones"`
	} `yaml:"aws"`

	Logging struct {
		Level  string `yaml:"level"`
		Output string `yaml:"output"`
	} `yaml:"logging"`

	// Docker (leitura de logs de container)
	Docker struct {
		Enabled     bool     `yaml:"enabled"`        // habilita captura via docker
		Container   string   `yaml:"container"`      // nome/ID do container
		ReadStdLogs bool     `yaml:"read_stdlogs"`   // acompanhar stdout/stderr (docker logs -f)
		TailFiles   bool     `yaml:"tail_files"`     // tail -F dentro do container
		Files       []string `yaml:"files"`          // lista de paths dentro do container
	} `yaml:"docker"`

	// Notificações (Email)
	Notifications Notifications `yaml:"notifications"`
}

// Notifications agrega todos os canais
type Notifications struct {
	Email    EmailConfig    `yaml:"email"`
}

type EmailConfig struct {
	FromEmail     string `yaml:"from_email"`      
	FromName      string `yaml:"from_name"`       
	To            string `yaml:"to"`             
	SubjectPrefix string `yaml:"subject_prefix"`  
}

// =====================
// Carregamento
// =====================

// LoadConfig reads the YAML configuration from the given path
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	cfg := &Config{}
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config YAML: %v", err)
	}

	// -------- Defaults --------
	// Monitoring
	if cfg.Monitoring.IntervalSeconds == 0 {
		cfg.Monitoring.IntervalSeconds = 60
	}
	if cfg.Monitoring.TimeoutSeconds == 0 {
		cfg.Monitoring.TimeoutSeconds = 30
	}
	if cfg.Monitoring.AlertThreshold == 0 {
		cfg.Monitoring.AlertThreshold = 5
	}

	// Endpoints
	if strings.TrimSpace(cfg.Endpoints.AWSEndpoint) == "" {
		cfg.Endpoints.AWSEndpoint = "https://route53.amazonaws.com/"
	}

	// AWS
	if strings.TrimSpace(cfg.AWS.Region) == "" {
		cfg.AWS.Region = "us-east-1"
	}

	// Docker
	if cfg.Docker.Enabled {
		if !cfg.Docker.ReadStdLogs && !cfg.Docker.TailFiles {
			// se habilitado e nenhum modo escolhido, padrão: stdout/stderr
			cfg.Docker.ReadStdLogs = true
		}
		if len(cfg.Docker.Files) > 0 {
			// normaliza caminhos (trim de espaços)
			out := make([]string, 0, len(cfg.Docker.Files))
			for _, f := range cfg.Docker.Files {
				if s := strings.TrimSpace(f); s != "" {
					out = append(out, s)
				}
			}
			cfg.Docker.Files = out
		}
	}

	// Notifications defaults (não obrigatórios)
	if strings.TrimSpace(cfg.Notifications.Email.FromName) == "" {
		cfg.Notifications.Email.FromName = "Doppel Alerts"
	}
	if strings.TrimSpace(cfg.Notifications.Email.SubjectPrefix) == "" {
		cfg.Notifications.Email.SubjectPrefix = "[Doppel]"
	}

	return cfg, nil
}

// =====================
// Validações
// =====================

// ValidateConfig validates the configuration for required fields
func (c *Config) ValidateConfig() error {
	// --- Providers (AWS) ---
	hasAWS := c.APIKeys.AWSAccessKey != "" && c.APIKeys.AWSSecretKey != "" && len(c.AWS.Route53Zones) > 0

	if hasAWS {
		if strings.TrimSpace(c.APIKeys.AWSAccessKey) == "" {
			return fmt.Errorf("AWS access key is required when AWS Route53 zones are configured")
		}
		if strings.TrimSpace(c.APIKeys.AWSSecretKey) == "" {
			return fmt.Errorf("AWS secret key is required when AWS Route53 zones are configured")
		}
		if strings.TrimSpace(c.AWS.Region) == "" {
			return fmt.Errorf("AWS region is required when AWS is configured")
		}
		for i, zone := range c.AWS.Route53Zones {
			if strings.TrimSpace(zone) == "" {
				return fmt.Errorf("AWS Route53 zone #%d cannot be empty", i+1)
			}
		}
	}

	// --- Monitoring ---
	if c.Monitoring.IntervalSeconds < 30 {
		return fmt.Errorf("monitoring interval must be at least 30 seconds")
	}
	if c.Monitoring.TimeoutSeconds < 10 {
		return fmt.Errorf("timeout must be at least 10 seconds")
	}
	if c.Monitoring.AlertThreshold < 1 {
		return fmt.Errorf("alert threshold must be at least 1")
	}

	// --- Docker ---
	if c.Docker.Enabled {
		if strings.TrimSpace(c.Docker.Container) == "" {
			return fmt.Errorf("docker.container is required when docker.enabled is true")
		}
		if !c.Docker.ReadStdLogs && !c.Docker.TailFiles {
			return fmt.Errorf("docker: enable at least one of read_stdlogs or tail_files")
		}
		if c.Docker.TailFiles && len(c.Docker.Files) == 0 {
			return fmt.Errorf("docker: tail_files is true but no docker.files provided")
		}
	}

	// --- Notifications ---
	// Não tornamos obrigatório ter um canal; apenas um aviso (deixe como comentário ou log no main).
	// Se quiser forçar e-mail, descomente abaixo:
	/*
		if strings.TrimSpace(c.Notifications.Email.FromEmail) == "" ||
			strings.TrimSpace(c.Notifications.Email.To) == "" {
			return fmt.Errorf("notifications.email.from_email and notifications.email.to are required for email alerts")
		}
	*/

	return nil
}

// =====================
// Helpers de Provedores
// =====================

// GetProviderZones returns the zones/domains for a specific provider
func (c *Config) GetProviderZones(providerName string) []string {
	switch providerName {
	case "AWS Route53":
		return c.AWS.Route53Zones
	default:
		return []string{}
	}
}

// HasAWS returns true if AWS Route53 is configured
func (c *Config) HasAWS() bool {
	return c.APIKeys.AWSAccessKey != "" && c.APIKeys.AWSSecretKey != "" && len(c.AWS.Route53Zones) > 0
}

// GetEnabledProviders returns a list of enabled DNS providers
func (c *Config) GetEnabledProviders() []string {
	providers := []string{}
	if c.HasAWS() {
		providers = append(providers, "AWS Route53")
	}
	return providers
}

// GetProviderCount returns the number of configured DNS providers
func (c *Config) GetProviderCount() int {
	count := 0
	if c.HasAWS() {
		count++
	}
	return count
}

// =====================
// Helpers Docker
// =====================

func (c *Config) HasDocker() bool {
	return c.Docker.Enabled && strings.TrimSpace(c.Docker.Container) != ""
}
func (c *Config) DockerContainer() string {
	return c.Docker.Container
}
func (c *Config) DockerFiles() []string {
	return append([]string(nil), c.Docker.Files...)
}
func (c *Config) DockerReadStdLogs() bool {
	return c.Docker.ReadStdLogs
}
func (c *Config) DockerTailFiles() bool {
	return c.Docker.TailFiles
}

// =====================
// Helpers Notifications
// =====================

func (c *Config) HasEmailNotifications() bool {
	return strings.TrimSpace(c.Notifications.Email.FromEmail) != "" &&
		strings.TrimSpace(c.Notifications.Email.To) != ""
}
func (c *Config) EmailFrom() string {
	return strings.TrimSpace(c.Notifications.Email.FromEmail)
}
func (c *Config) EmailFromName() string {
	if s := strings.TrimSpace(c.Notifications.Email.FromName); s != "" {
		return s
	}
	return "Doppel Alerts"
}
func (c *Config) EmailTo() string {
	return strings.TrimSpace(c.Notifications.Email.To)
}
func (c *Config) EmailSubjectPrefix() string {
	if s := strings.TrimSpace(c.Notifications.Email.SubjectPrefix); s != "" {
		return s
	}
	return "[Doppel]"
}

