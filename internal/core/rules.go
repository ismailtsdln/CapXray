package core

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rules configuration
type Rules struct {
	DNS struct {
		MaxDomainLength  int     `yaml:"max_domain_length"`
		EntropyThreshold float64 `yaml:"entropy_threshold"`
	} `yaml:"dns"`
	Beaconing struct {
		MinHits   int    `yaml:"min_hits"`
		MaxJitter string `yaml:"max_jitter"`
	} `yaml:"beaconing"`
	HTTP struct {
		SuspiciousUAs []string `yaml:"suspicious_uas"`
	} `yaml:"http"`
}

// LoadRules loads configuration from a YAML file
func LoadRules(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}

	return &rules, nil
}
