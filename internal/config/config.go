// Package config loads proxy settings from a YAML file and the environment.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Anwesha33/pii-shield/internal/detect"
	"github.com/Anwesha33/pii-shield/internal/policy"
)

// Config is the full proxy configuration.
type Config struct {
	// Listen is the address the proxy binds to.
	Listen string `yaml:"listen"`

	// Upstream is the base URL of the model provider, expected to expose an
	// OpenAI-compatible surface. Keeping this configurable is what makes the
	// proxy provider-agnostic: pointing it at a different vendor is a config
	// change, not a code change.
	Upstream string `yaml:"upstream"`

	// UpstreamAPIKeyEnv names the environment variable holding the upstream
	// credential. The key itself is never read from the config file, so a
	// committed config can never carry a secret.
	UpstreamAPIKeyEnv string `yaml:"upstream_api_key_env"`

	// UpstreamAuthStyle selects how the credential is presented: "bearer" for
	// an Authorization header, "query" for a ?key= parameter (Google's native
	// API).
	UpstreamAuthStyle string `yaml:"upstream_auth_style"`

	// Timeout bounds a single upstream request.
	Timeout time.Duration `yaml:"timeout"`

	// ScanResponses enables egress scanning for values that were never in the
	// request.
	ScanResponses bool `yaml:"scan_responses"`

	// LogDecisions writes a per-request audit line describing what was redacted.
	// The line records entity types and counts, never values.
	LogDecisions bool `yaml:"log_decisions"`

	// DefaultAction applies to entity types with no explicit rule.
	DefaultAction policy.Action `yaml:"default_action"`

	// Rules overrides the default policy per entity type.
	Rules []policy.Rule `yaml:"rules"`
}

// Default returns a configuration that is safe to run with no config file.
func Default() *Config {
	return &Config{
		Listen:            ":8080",
		Upstream:          "https://generativelanguage.googleapis.com/v1beta/openai",
		UpstreamAPIKeyEnv: "GEMINI_API_KEY",
		UpstreamAuthStyle: "bearer",
		Timeout:           60 * time.Second,
		ScanResponses:     true,
		LogDecisions:      true,
		DefaultAction:     policy.Redact,
	}
}

// Load reads a YAML config, falling back to defaults for anything unset.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate rejects configurations that would fail confusingly at request time.
func (c *Config) Validate() error {
	if c.Upstream == "" {
		return fmt.Errorf("upstream must be set")
	}
	switch c.UpstreamAuthStyle {
	case "bearer", "query", "none":
	default:
		return fmt.Errorf("upstream_auth_style must be bearer, query or none; got %q", c.UpstreamAuthStyle)
	}
	valid := map[policy.Action]bool{policy.Redact: true, policy.Mask: true, policy.Block: true, policy.Allow: true}
	for _, r := range c.Rules {
		if !valid[r.Action] {
			return fmt.Errorf("rule for %s has unknown action %q", r.Type, r.Action)
		}
		if !knownType(r.Type) {
			return fmt.Errorf("rule refers to unknown entity type %q", r.Type)
		}
	}
	return nil
}

func knownType(t detect.EntityType) bool {
	for _, k := range detect.AllTypes {
		if k == t {
			return true
		}
	}
	return false
}

// Policy builds the runtime policy from the configuration.
func (c *Config) Policy() *policy.Policy {
	p := policy.Default()
	if c.DefaultAction != "" {
		p.Default = c.DefaultAction
	}
	for _, r := range c.Rules {
		if r.MinConfidence == 0 {
			r.MinConfidence = 0.5
		}
		p.Rules[string(r.Type)] = r
	}
	return p
}

// UpstreamKey reads the upstream credential from the environment.
func (c *Config) UpstreamKey() string {
	if c.UpstreamAPIKeyEnv == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(c.UpstreamAPIKeyEnv))
}
