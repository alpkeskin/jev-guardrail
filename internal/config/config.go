// Package config loads service configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the service configuration.
type Config struct {
	Addr         string
	MetricsAddr  string // empty disables the metrics listener
	PolicyDir    string
	LogLevel     string
	LogFormat    string
	MaxBodyBytes int64

	AuthDisabled bool
	APIKeys      string

	JevURL          string
	JevAPIKey       string
	JevAuthHeader   string
	JevAuthScheme   string
	JevTimeout      time.Duration
	JevEvaluatePath string
	JevHealthPath   string // empty disables Jev health checks

	JevMaxConcurrency      int
	JevQueueTimeout        time.Duration
	JevBreakerThreshold    int // 0 disables the circuit breaker
	JevBreakerOpenTimeout  time.Duration
	JevBreakerHalfOpenReqs int

	ReadyCheckJev   bool
	ShutdownDelay   time.Duration
	ShutdownTimeout time.Duration
}

// loader accumulates errors while reading variables.
type loader struct {
	getenv func(string) string
	errs   []error
}

func (l *loader) fail(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) str(key, def string) string {
	if v := strings.TrimSpace(l.getenv(key)); v != "" {
		return v
	}
	return def
}

// optional returns the value, or "" when unset or set to "-".
func (l *loader) optional(key, def string) string {
	if v := l.str(key, def); v != "-" {
		return v
	}
	return ""
}

func (l *loader) duration(key string, def time.Duration, allowZero bool) time.Duration {
	v := strings.TrimSpace(l.getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || (d == 0 && !allowZero) {
		l.fail("%s: invalid duration %q", key, v)
		return def
	}
	return d
}

func (l *loader) integer(key string, def, min int64) int64 {
	v := strings.TrimSpace(l.getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < min {
		l.fail("%s: invalid integer %q (minimum %d)", key, v, min)
		return def
	}
	return n
}

func (l *loader) boolean(key string, def bool) bool {
	v := strings.TrimSpace(l.getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail("%s: invalid boolean %q", key, v)
		return def
	}
	return b
}

// secret reads a value from KEY or from the file named by KEY_FILE
// (e.g. a mounted Kubernetes secret). Setting both is an error.
// A missing or empty secret is an error.
func (l *loader) secret(key string) string {
	val, file := strings.TrimSpace(l.getenv(key)), strings.TrimSpace(l.getenv(key+"_FILE"))
	switch {
	case val != "" && file != "":
		l.fail("%s and %s_FILE are mutually exclusive", key, key)
		return ""
	case file != "":
		data, err := os.ReadFile(file) //nolint:gosec // operator-configured secret path
		if err != nil {
			l.fail("%s_FILE: %v", key, err)
			return ""
		}
		val = strings.TrimSpace(string(data))
		if val == "" {
			l.fail("%s_FILE: file is empty", key)
		}
		return val
	case val == "":
		l.fail("%s or %s_FILE is required", key, key)
	}
	return val
}

// Load reads configuration using getenv (os.Getenv when nil).
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	l := &loader{getenv: getenv}

	c := Config{
		Addr:         l.str("GUARDRAIL_ADDR", ":8080"),
		MetricsAddr:  l.optional("GUARDRAIL_METRICS_ADDR", ":9090"),
		PolicyDir:    l.str("GUARDRAIL_POLICY_DIR", "policies"),
		LogLevel:     l.str("GUARDRAIL_LOG_LEVEL", "info"),
		LogFormat:    l.str("GUARDRAIL_LOG_FORMAT", "json"),
		MaxBodyBytes: l.integer("GUARDRAIL_MAX_BODY_BYTES", 1<<20, 1),
		AuthDisabled: l.boolean("GUARDRAIL_AUTH_DISABLED", false),
		APIKeys:      strings.TrimSpace(getenv("GUARDRAIL_API_KEYS")),

		JevURL:          l.str("JEV_URL", ""),
		JevAPIKey:       l.secret("JEV_API_KEY"),
		JevAuthHeader:   l.str("JEV_AUTH_HEADER", "Authorization"),
		JevTimeout:      l.duration("JEV_TIMEOUT", 5*time.Second, false),
		JevEvaluatePath: l.str("JEV_EVALUATE_PATH", "/v1/evaluate"),
		JevHealthPath:   l.optional("JEV_HEALTH_PATH", "/health"),

		JevMaxConcurrency:      int(l.integer("JEV_MAX_CONCURRENCY", 100, 1)),
		JevQueueTimeout:        l.duration("JEV_QUEUE_TIMEOUT", 250*time.Millisecond, true),
		JevBreakerThreshold:    int(l.integer("JEV_CIRCUIT_BREAKER_THRESHOLD", 5, 0)),
		JevBreakerOpenTimeout:  l.duration("JEV_CIRCUIT_BREAKER_OPEN_TIMEOUT", 15*time.Second, false),
		JevBreakerHalfOpenReqs: int(l.integer("JEV_CIRCUIT_BREAKER_HALF_OPEN_REQUESTS", 1, 1)),

		ReadyCheckJev:   l.boolean("GUARDRAIL_READY_CHECK_JEV", true),
		ShutdownDelay:   l.duration("GUARDRAIL_SHUTDOWN_DELAY", 5*time.Second, true),
		ShutdownTimeout: l.duration("GUARDRAIL_SHUTDOWN_TIMEOUT", 15*time.Second, false),
	}

	// The scheme defaults to Bearer only for the Authorization header.
	defScheme := ""
	if strings.EqualFold(c.JevAuthHeader, "Authorization") {
		defScheme = "Bearer"
	}
	c.JevAuthScheme = l.optional("JEV_AUTH_SCHEME", defScheme)

	if path := strings.TrimSpace(getenv("GUARDRAIL_API_KEYS_FILE")); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-configured secret path
		if err != nil {
			l.fail("GUARDRAIL_API_KEYS_FILE: %v", err)
		} else {
			// One "name:key" or "key" per line; blank lines and # comments
			// are skipped so they can never become valid keys.
			var lines []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.Contains(line, ",") {
					l.fail("GUARDRAIL_API_KEYS_FILE: entries must not contain commas")
					continue
				}
				lines = append(lines, line)
			}
			if extra := strings.Join(lines, ","); extra != "" {
				if c.APIKeys != "" {
					c.APIKeys += ","
				}
				c.APIKeys += extra
			}
		}
	}

	if c.JevURL == "" {
		l.fail("JEV_URL is required")
	}
	if c.AuthDisabled && c.APIKeys != "" {
		// Refuse ambiguous configuration rather than silently ignoring keys.
		l.fail("GUARDRAIL_AUTH_DISABLED=true conflicts with configured API keys")
	}
	if !c.AuthDisabled && c.APIKeys == "" {
		l.fail("authentication requires GUARDRAIL_API_KEYS or GUARDRAIL_API_KEYS_FILE (or GUARDRAIL_AUTH_DISABLED=true)")
	}
	if c.MetricsAddr != "" && c.MetricsAddr == c.Addr {
		l.fail("GUARDRAIL_METRICS_ADDR must differ from GUARDRAIL_ADDR")
	}
	if err := errors.Join(l.errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}
