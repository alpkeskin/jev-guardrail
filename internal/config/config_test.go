package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// base is the minimal valid environment.
func base(extra map[string]string) func(string) string {
	m := map[string]string{"JEV_URL": "http://jev:8000", "JEV_API_KEY": "jev-key", "GUARDRAIL_API_KEYS": "k"}
	for k, v := range extra {
		if v == "<unset>" {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(base(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Addr: ":8080", MetricsAddr: ":9090", PolicyDir: "policies", LogLevel: "info", LogFormat: "json",
		MaxBodyBytes: 1 << 20, APIKeys: "k",
		JevURL: "http://jev:8000", JevAPIKey: "jev-key", JevAuthHeader: "Authorization", JevAuthScheme: "Bearer",
		JevTimeout: 5 * time.Second, JevEvaluatePath: "/v1/evaluate", JevHealthPath: "/health",
		JevMaxConcurrency: 100, JevQueueTimeout: 250 * time.Millisecond,
		JevBreakerThreshold: 5, JevBreakerOpenTimeout: 15 * time.Second, JevBreakerHalfOpenReqs: 1,
		ReadyCheckJev: true, ShutdownDelay: 5 * time.Second, ShutdownTimeout: 15 * time.Second,
	}
	if c != want {
		t.Fatalf("defaults:\n got %+v\nwant %+v", c, want)
	}
}

func TestLoadOverrides(t *testing.T) {
	keyFile := writeFile(t, "b:fedcba9876543210\n")
	c, err := Load(base(map[string]string{
		"JEV_TIMEOUT":                      "750ms",
		"JEV_HEALTH_PATH":                  "-",
		"GUARDRAIL_METRICS_ADDR":           "-",
		"GUARDRAIL_API_KEYS":               "a:0123456789abcdef",
		"GUARDRAIL_API_KEYS_FILE":          keyFile,
		"GUARDRAIL_MAX_BODY_BYTES":         "2048",
		"GUARDRAIL_SHUTDOWN_DELAY":         "0s",
		"GUARDRAIL_READY_CHECK_JEV":        "false",
		"JEV_MAX_CONCURRENCY":              "8",
		"JEV_QUEUE_TIMEOUT":                "0",
		"JEV_CIRCUIT_BREAKER_THRESHOLD":    "0",
		"JEV_CIRCUIT_BREAKER_OPEN_TIMEOUT": "30s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.JevTimeout != 750*time.Millisecond || c.JevHealthPath != "" || c.MetricsAddr != "" || c.MaxBodyBytes != 2048 ||
		c.APIKeys != "a:0123456789abcdef,b:fedcba9876543210" || c.ShutdownDelay != 0 || c.ReadyCheckJev ||
		c.JevMaxConcurrency != 8 || c.JevQueueTimeout != 0 || c.JevBreakerThreshold != 0 || c.JevBreakerOpenTimeout != 30*time.Second {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestJevAPIKey(t *testing.T) {
	keyFile := writeFile(t, "  file-key\n")
	c, err := Load(base(map[string]string{"JEV_API_KEY": "<unset>", "JEV_API_KEY_FILE": keyFile}))
	if err != nil || c.JevAPIKey != "file-key" {
		t.Fatalf("key=%q err=%v", c.JevAPIKey, err)
	}

	tests := map[string]map[string]string{
		"JEV_API_KEY or JEV_API_KEY_FILE is required":  {"JEV_API_KEY": "<unset>"},
		"JEV_API_KEY or JEV_API_KEY_FILE is required.": {"JEV_API_KEY": "   "},
		"mutually exclusive":                           {"JEV_API_KEY_FILE": keyFile},
		"file is empty":                                {"JEV_API_KEY": "<unset>", "JEV_API_KEY_FILE": writeFile(t, "\n\n")},
		"no such file":                                 {"JEV_API_KEY": "<unset>", "JEV_API_KEY_FILE": "/nonexistent/key"},
	}
	for want, env := range tests {
		want = strings.TrimSuffix(want, ".")
		if _, err := Load(base(env)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}

func TestJevAuthScheme(t *testing.T) {
	cases := []struct{ header, scheme, wantScheme string }{
		{"", "", "Bearer"},
		{"authorization", "", "Bearer"},
		{"X-API-Key", "", ""},
		{"Authorization", "Token", "Token"},
		{"Authorization", "-", ""},
	}
	for _, tc := range cases {
		c, err := Load(base(map[string]string{"JEV_AUTH_HEADER": tc.header, "JEV_AUTH_SCHEME": tc.scheme}))
		if err != nil || c.JevAuthScheme != tc.wantScheme {
			t.Errorf("header=%q scheme=%q: got %q err=%v", tc.header, tc.scheme, c.JevAuthScheme, err)
		}
	}
}

func TestKeysFileSkipsCommentsAndBlankLines(t *testing.T) {
	keyFile := writeFile(t, "# production keys for the litellm gateway\n\n  litellm:0123456789abcdef  \r\n# another comment line here\n")
	c, err := Load(base(map[string]string{"GUARDRAIL_API_KEYS": "<unset>", "GUARDRAIL_API_KEYS_FILE": keyFile}))
	if err != nil {
		t.Fatal(err)
	}
	if c.APIKeys != "litellm:0123456789abcdef" {
		t.Fatalf("APIKeys = %q", c.APIKeys)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]map[string]string{
		"JEV_URL is required":                {"JEV_URL": "<unset>"},
		"authentication requires":            {"GUARDRAIL_API_KEYS": "<unset>"},
		"comments only file":                 {"GUARDRAIL_API_KEYS": "<unset>", "GUARDRAIL_API_KEYS_FILE": "COMMENTS"},
		"conflicts with configured API keys": {"GUARDRAIL_AUTH_DISABLED": "true"},
		"JEV_TIMEOUT":                        {"JEV_TIMEOUT": "soon"},
		"JEV_TIMEOUT.":                       {"JEV_TIMEOUT": "0s"},
		"GUARDRAIL_MAX_BODY_BYTES":           {"GUARDRAIL_MAX_BODY_BYTES": "-1"},
		"GUARDRAIL_AUTH_DISABLED":            {"GUARDRAIL_AUTH_DISABLED": "maybe"},
		"JEV_MAX_CONCURRENCY":                {"JEV_MAX_CONCURRENCY": "0"},
		"JEV_CIRCUIT_BREAKER_THRESHOLD":      {"JEV_CIRCUIT_BREAKER_THRESHOLD": "-1"},
		"GUARDRAIL_SHUTDOWN_DELAY":           {"GUARDRAIL_SHUTDOWN_DELAY": "-5s"},
		"GUARDRAIL_METRICS_ADDR must differ": {"GUARDRAIL_METRICS_ADDR": ":8080"},
		"GUARDRAIL_READY_CHECK_JEV":          {"GUARDRAIL_READY_CHECK_JEV": "sometimes"},
	}
	comments := writeFile(t, "# only a comment that is long enough to be a key\n")
	for want, env := range tests {
		if env["GUARDRAIL_API_KEYS_FILE"] == "COMMENTS" {
			env["GUARDRAIL_API_KEYS_FILE"] = comments
			want = "authentication requires"
		}
		want = strings.TrimSuffix(want, ".")
		if _, err := Load(base(env)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}
