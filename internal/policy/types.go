// Package policy loads, validates and resolves YAML security policies.
package policy

import "github.com/alpkeskin/jev-guardrail/internal/guardrail"

// Policy is the validated policy used by the guardrail pipeline.
type Policy = guardrail.Policy

// DefaultClientID is the client_id the mandatory default policy must declare.
const DefaultClientID = "default"

// DefaultFileName is the mandatory default policy file.
const DefaultFileName = "default.yaml"

// SupportedVersion is the only policy schema version understood.
const SupportedVersion = "1"

// document is the on-disk YAML schema of a policy file.
type document struct {
	Version     string               `yaml:"version"`
	ClientID    string               `yaml:"client_id"`
	Description string               `yaml:"description"`
	Rules       map[string]ruleEntry `yaml:"rules"`
}

type ruleEntry struct {
	// Enabled defaults to true when omitted.
	Enabled   *bool    `yaml:"enabled"`
	Threshold *float64 `yaml:"threshold"`
	Action    string   `yaml:"action"`
}
