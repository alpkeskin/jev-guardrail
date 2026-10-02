package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"JEV_URL": "http://jev:8000", "GUARDRAIL_API_KEYS": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":8080" || c.PolicyDir != "policies" || c.JevTimeout != 5*time.Second ||
		c.JevEvaluatePath != "/v1/evaluate" || c.JevHealthPath != "/health" || c.MaxBodyBytes != 1<<20 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadOverrides(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "keys")
	_ = os.WriteFile(keyFile, []byte("b:fedcba9876543210\n"), 0o600)
	c, err := Load(env(map[string]string{
		"JEV_URL":                  "http://jev",
		"JEV_TIMEOUT":              "750ms",
		"JEV_HEALTH_PATH":          "-",
		"GUARDRAIL_API_KEYS":       "a:0123456789abcdef",
		"GUARDRAIL_API_KEYS_FILE":  keyFile,
		"GUARDRAIL_MAX_BODY_BYTES": "2048",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.JevTimeout != 750*time.Millisecond || c.JevHealthPath != "" || c.MaxBodyBytes != 2048 ||
		c.APIKeys != "a:0123456789abcdef,b:fedcba9876543210" {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]map[string]string{
		"JEV_URL is required":      {"GUARDRAIL_API_KEYS": "k"},
		"authentication requires":  {"JEV_URL": "http://jev"},
		"JEV_TIMEOUT":              {"JEV_URL": "http://jev", "GUARDRAIL_AUTH_DISABLED": "true", "JEV_TIMEOUT": "soon"},
		"GUARDRAIL_MAX_BODY_BYTES": {"JEV_URL": "http://jev", "GUARDRAIL_AUTH_DISABLED": "true", "GUARDRAIL_MAX_BODY_BYTES": "-1"},
		"GUARDRAIL_AUTH_DISABLED":  {"JEV_URL": "http://jev", "GUARDRAIL_AUTH_DISABLED": "maybe"},
	}
	for want, e := range tests {
		if _, err := Load(env(e)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}
