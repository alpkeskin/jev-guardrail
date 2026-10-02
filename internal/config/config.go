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
	PolicyDir    string
	LogLevel     string
	LogFormat    string
	MaxBodyBytes int64

	AuthDisabled bool
	APIKeys      string

	JevURL          string
	JevAPIKey       string
	JevTimeout      time.Duration
	JevEvaluatePath string
	JevHealthPath   string

	ShutdownTimeout time.Duration
}

// Load reads configuration using getenv (os.Getenv when nil).
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	str := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	dur := func(key string, def time.Duration) time.Duration {
		v := getenv(key)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: invalid positive duration %q", key, v))
			return def
		}
		return d
	}

	c := Config{
		Addr:            str("GUARDRAIL_ADDR", ":8080"),
		PolicyDir:       str("GUARDRAIL_POLICY_DIR", "policies"),
		LogLevel:        str("GUARDRAIL_LOG_LEVEL", "info"),
		LogFormat:       str("GUARDRAIL_LOG_FORMAT", "json"),
		MaxBodyBytes:    1 << 20,
		APIKeys:         getenv("GUARDRAIL_API_KEYS"),
		JevURL:          str("JEV_URL", ""),
		JevAPIKey:       getenv("JEV_API_KEY"),
		JevTimeout:      dur("JEV_TIMEOUT", 5*time.Second),
		JevEvaluatePath: str("JEV_EVALUATE_PATH", "/v1/evaluate"),
		JevHealthPath:   str("JEV_HEALTH_PATH", "/health"),
		ShutdownTimeout: dur("GUARDRAIL_SHUTDOWN_TIMEOUT", 15*time.Second),
	}
	if v := getenv("JEV_HEALTH_PATH"); v == "-" {
		c.JevHealthPath = ""
	}
	if v := getenv("GUARDRAIL_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("GUARDRAIL_MAX_BODY_BYTES: invalid positive integer %q", v))
		} else {
			c.MaxBodyBytes = n
		}
	}
	if v := getenv("GUARDRAIL_AUTH_DISABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("GUARDRAIL_AUTH_DISABLED: invalid boolean %q", v))
		}
		c.AuthDisabled = b
	}
	if path := getenv("GUARDRAIL_API_KEYS_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("GUARDRAIL_API_KEYS_FILE: %w", err))
		} else {
			lines := strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' || r == '\r' })
			extra := strings.Join(lines, ",")
			if c.APIKeys != "" && extra != "" {
				c.APIKeys += ","
			}
			c.APIKeys += extra
		}
	}

	if c.JevURL == "" {
		errs = append(errs, errors.New("JEV_URL is required"))
	}
	if !c.AuthDisabled && strings.TrimSpace(c.APIKeys) == "" {
		errs = append(errs, errors.New("authentication requires GUARDRAIL_API_KEYS or GUARDRAIL_API_KEYS_FILE (or GUARDRAIL_AUTH_DISABLED=true)"))
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}
