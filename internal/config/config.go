package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all service configuration. Load via LoadConfig.
// SECURITY: Never log this struct - it may contain credentials.
type Config struct {
	ServiceName string         `yaml:"service_name"`
	HTTP        HTTPConfig     `yaml:"http"`
	Postgres    PostgresConfig `yaml:"postgres"`
	Redis       RedisConfig    `yaml:"redis"`
	Kafka       KafkaConfig    `yaml:"kafka"`
	S3          S3Config       `yaml:"s3"`
	Okta        OktaConfig     `yaml:"okta"`
	M365        M365Config     `yaml:"m365"`
	Policy      PolicyConfig   `yaml:"policy"`
}

type HTTPConfig struct {
	ListenAddr    string `yaml:"listen_addr"`
	ReadTimeoutS  int    `yaml:"read_timeout_s"`
	WriteTimeoutS int    `yaml:"write_timeout_s"`
	IdleTimeoutS  int    `yaml:"idle_timeout_s"`
}

type PostgresConfig struct {
	DSN      string `yaml:"dsn"`
	MaxConns int32  `yaml:"max_conns"`
	MinConns int32  `yaml:"min_conns"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type KafkaConfig struct {
	Brokers               []string `yaml:"brokers"`
	TopicRawEvents        string   `yaml:"topic_raw_events"`
	TopicNormalizedEvents string   `yaml:"topic_normalized_events"`
	TopicRiskSignals      string   `yaml:"topic_risk_signals"`
	TopicActionRecs       string   `yaml:"topic_action_recommendations"`
	TopicActionRequests   string   `yaml:"topic_action_requests"`
	ConsumerGroupID       string   `yaml:"consumer_group_id"`
}

type S3Config struct {
	RawBucket      string `yaml:"raw_bucket"`
	ReportsBucket  string `yaml:"reports_bucket"`
	Endpoint       string `yaml:"endpoint"` // MinIO in dev
	Region         string `yaml:"region"`
	ForcePathStyle bool   `yaml:"force_path_style"`
}

// OktaConfig - SECURITY: Token is sensitive; load from Secrets Manager in prod.
type OktaConfig struct {
	BaseURL string `yaml:"base_url"`
	Token   string `yaml:"token"` // env override: OKTA_TOKEN
}

// M365Config - SECURITY: Credentials are sensitive; load from Secrets Manager in prod.
type M365Config struct {
	TenantID     string `yaml:"tenant_id"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"` // env override: M365_CLIENT_SECRET
}

type PolicyConfig struct {
	AllowlistPath  string `yaml:"allowlist_path"`
	DisallowedPath string `yaml:"disallowed_path"`
}

// LoadConfig loads configuration from a YAML file with environment variable overrides.
// Environment variables override YAML values: use format SERVICE_FIELD (uppercased, dots→underscores).
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}

	if path != "" {
		data, err := os.ReadFile(path) // #nosec G304 - path is from trusted args
		if err != nil {
			return nil, fmt.Errorf("reading config file %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Environment overrides
	applyEnvOverrides(cfg)

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("SERVICE_NAME"); v != "" {
		cfg.ServiceName = v
	}
	if v := os.Getenv("HTTP_LISTEN_ADDR"); v != "" {
		cfg.HTTP.ListenAddr = v
	}
	if v := os.Getenv("POSTGRES_DSN"); v != "" {
		cfg.Postgres.DSN = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("KAFKA_BROKERS"); v != "" {
		cfg.Kafka.Brokers = strings.Split(v, ",")
	}
	if v := os.Getenv("OKTA_BASE_URL"); v != "" {
		cfg.Okta.BaseURL = v
	}
	// SECURITY: load secrets from env in dev; Secrets Manager in prod
	if v := os.Getenv("OKTA_TOKEN"); v != "" {
		cfg.Okta.Token = v
	}
	if v := os.Getenv("M365_CLIENT_SECRET"); v != "" {
		cfg.M365.ClientSecret = v
	}
	if v := os.Getenv("S3_ENDPOINT"); v != "" {
		cfg.S3.Endpoint = v
	}
	if v := os.Getenv("AWS_REGION"); v != "" {
		cfg.S3.Region = v
	}
}

func (c *Config) validate() error {
	var errs []string
	if c.ServiceName == "" {
		errs = append(errs, "service_name is required")
	}
	if c.HTTP.ListenAddr == "" {
		c.HTTP.ListenAddr = ":8080"
	}
	if c.HTTP.ReadTimeoutS == 0 {
		c.HTTP.ReadTimeoutS = 30
	}
	if c.HTTP.WriteTimeoutS == 0 {
		c.HTTP.WriteTimeoutS = 30
	}
	if c.Postgres.MaxConns == 0 {
		c.Postgres.MaxConns = 10
	}
	if c.Postgres.MinConns == 0 {
		c.Postgres.MinConns = 2
	}
	if len(c.Kafka.Brokers) == 0 {
		c.Kafka.Brokers = []string{"localhost:9092"}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
