package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config is the main configuration struct.
type Config struct {
	Scanner    ScannerConfig    `yaml:"scanner"`
	Database   string           `yaml:"database"`
	Redis      RedisConfig      `yaml:"redis"`
	Blockchain BlockchainConfig `yaml:"blockchain"`
	IPFS       IPFSConfig       `yaml:"ipfs"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Security   SecurityConfig   `yaml:"security"`
}

// ScannerConfig is the scanner configuration struct.
type ScannerConfig struct {
	Name                string          `yaml:"name"`
	Version             string          `yaml:"version"`
	Mode                string          `yaml:"mode"`
	Scan                ScanConfig      `yaml:"scan"`
	Modules             ModulesConfig   `yaml:"modules"`
	AI                  AIConfig        `yaml:"ai"`
	Platforms           PlatformsConfig `yaml:"platforms"`
	Kubernetes          KubernetesConfig `yaml:"kubernetes"`
	Distributed         DistributedConfig `yaml:"distributed"`
}

// ScanConfig is the scan configuration struct.
type ScanConfig struct {
	Timeout              string `yaml:"timeout"`
	MaxConcurrentScans   int    `yaml:"max_concurrent_scans"`
	MaxWorkersPerScan    int    `yaml:"max_workers_per_scan"`
	RateLimit            int    `yaml:"rate_limit"`
	UserAgent            string `yaml:"user_agent"`
	FollowRedirects      bool   `yaml:"follow_redirects"`
	MaxRedirects         int    `yaml:"max_redirects"`
}

// ModulesConfig is the modules configuration struct.
type ModulesConfig struct {
	XSS  ModuleConfig `yaml:"xss"`
	SQLI ModuleConfig `yaml:"sqli"`
	SSRF ModuleConfig `yaml:"ssrf"`
	RCE  ModuleConfig `yaml:"rce"`
}

// ModuleConfig is the module configuration struct.
type ModuleConfig struct {
	Enabled             bool   `yaml:"enabled"`
	Timeout             string `yaml:"timeout"`
	MaxPayloads         int    `yaml:"max_payloads"`
	ValidateWithBrowser bool   `yaml:"validate_with_browser"`
	TestAllParameters   bool   `yaml:"test_all_parameters"`
	BlindDetection      bool   `yaml:"blind_detection"`
	CallbackURL         string `yaml:"callback_url"`
	TestInternalNetworks bool   `yaml:"test_internal_networks"`
	SafeMode            bool   `yaml:"safe_mode"`
}

// AIConfig is the AI configuration struct.
type AIConfig struct {
	DecisionEngine    DecisionEngineConfig `yaml:"decision_engine"`
	PayloadGeneration PayloadGenerationConfig `yaml:"payload_generation"`
}

// DecisionEngineConfig is the decision engine configuration struct.
type DecisionEngineConfig struct {
	Enabled     bool    `yaml:"enabled"`
	Model       string  `yaml:"model"`
	Temperature float64 `yaml:"temperature"`
	MaxTokens   int     `yaml:"max_tokens"`
}

// PayloadGenerationConfig is the payload generation configuration struct.
type PayloadGenerationConfig struct {
	Enabled          bool    `yaml:"enabled"`
	LearningEnabled  bool    `yaml:"learning_enabled"`
	SuccessThreshold float64 `yaml:"success_threshold"`
}

// PlatformsConfig is the platforms configuration struct.
type PlatformsConfig struct {
	HackerOne HackerOneConfig `yaml:"hackerone"`
	Bugcrowd  BugcrowdConfig  `yaml:"bugcrowd"`
}

// HackerOneConfig is the HackerOne configuration struct.
type HackerOneConfig struct {
	Enabled   bool   `yaml:"enabled"`
	APIKey    string `yaml:"api_key"`
	Username  string `yaml:"username"`
	AutoSubmit bool   `yaml:"auto_submit"`
}

// BugcrowdConfig is the Bugcrowd configuration struct.
type BugcrowdConfig struct {
	Enabled   bool   `yaml:"enabled"`
	APIKey    string `yaml:"api_key"`
	AutoSubmit bool   `yaml:"auto_submit"`
}

// RedisConfig is the Redis configuration struct.
type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// BlockchainConfig is the blockchain configuration struct.
type BlockchainConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Network         string `yaml:"network"`
	RPCURL          string `yaml:"rpc_url"`
	ContractAddress string `yaml:"contract_address"`
	PrivateKey      string `yaml:"private_key"`
	GasLimit        int    `yaml:"gas_limit"`
}

// IPFSConfig is the IPFS configuration struct.
type IPFSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	APIURL     string `yaml:"api_url"`
	GatewayURL string `yaml:"gateway_url"`
}

// MonitoringConfig is the monitoring configuration struct.
type MonitoringConfig struct {
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Grafana    GrafanaConfig    `yaml:"grafana"`
}

// PrometheusConfig is the Prometheus configuration struct.
type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// GrafanaConfig is the Grafana configuration struct.
type GrafanaConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// SecurityConfig is the security configuration struct.
type SecurityConfig struct {
	TLS            TLSConfig            `yaml:"tls"`
	Authentication AuthenticationConfig `yaml:"authentication"`
}

// TLSConfig is the TLS configuration struct.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// AuthenticationConfig is the authentication configuration struct.
type AuthenticationConfig struct {
	JWTSecret      string `yaml:"jwt_secret"`
	SessionTimeout string `yaml:"session_timeout"`
}

// KubernetesConfig is the Kubernetes configuration struct.
type KubernetesConfig struct {
	Namespace    string `yaml:"namespace"`
	ServiceName string `yaml:"service_name"`
}

// DistributedConfig is the distributed configuration struct.
type DistributedConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CoordinationService string `yaml:"coordination_service"`
}

// Load loads the configuration from the given path.
func Load(path string) (*Config, error) {
	// Read the configuration file.
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read configuration file: %w", err)
	}

	// Unmarshal the configuration.
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("could not unmarshal configuration: %w", err)
	}

	return &config, nil
}
