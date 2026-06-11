package engine

import (
	"encoding/json"
	"os"
)

type AegisConfig struct {
	ProxyPort    int      `json:"proxy_port"`
	OutputFile   string   `json:"output_file"`
	HTMLReport   string   `json:"html_report"`
	WordlistOut  string   `json:"wordlist_out"`
	CertDir      string   `json:"cert_dir"`
	
	Scope struct {
		Includes []string `json:"includes"`
		Excludes []string `json:"excludes"`
	} `json:"scope"`
	
	Modules struct {
		Enabled  []string `json:"enabled"`
		Disabled []string `json:"disabled"`
	} `json:"modules"`
	
	RateLimit struct {
		MinDelayMs  int `json:"min_delay_ms"`
		MaxParallel int `json:"max_parallel"`
	} `json:"rate_limit"`
	
	ScanProfile string `json:"scan_profile"` // fast, balanced, deep, custom
}

func LoadConfig(filename string) (*AegisConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	config := &AegisConfig{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	
	// Apply defaults
	if config.ProxyPort == 0 {
		config.ProxyPort = 8080
	}
	if config.OutputFile == "" {
		config.OutputFile = "aegis_report.json"
	}
	if config.CertDir == "" {
		config.CertDir = "./aegis-certs"
	}
	if config.RateLimit.MinDelayMs == 0 {
		config.RateLimit.MinDelayMs = 100
	}
	if config.RateLimit.MaxParallel == 0 {
		config.RateLimit.MaxParallel = 5
	}
	
	return config, nil
}

func SaveDefaultConfig(filename string) error {
	config := &AegisConfig{
		ProxyPort:  8080,
		OutputFile: "aegis_report.json",
		HTMLReport: "aegis_report.html",
		WordlistOut: "discovered_words.txt",
		CertDir:    "./aegis-certs",
		ScanProfile: "balanced",
	}
	
	config.Scope.Excludes = CommonOutOfScopeHosts()
	config.Modules.Enabled = []string{"all"}
	config.RateLimit.MinDelayMs = 100
	config.RateLimit.MaxParallel = 5
	
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filename, data, 0644)
}
