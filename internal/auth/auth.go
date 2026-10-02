// Package auth authenticates callers of the guardrail API.
//
// Authentication answers "who is calling?". It is deliberately separate
// from policy selection (X-Client-ID), which answers "which policy
// applies?" and is never trusted as an identity.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrUnauthenticated is returned when credentials are missing or invalid.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator identifies the caller of a request.
type Authenticator interface {
	// Authenticate returns a non-secret caller identifier.
	Authenticate(r *http.Request) (caller string, err error)
}

// Disabled accepts every request. Use only when authentication is enforced
// elsewhere (e.g. a service mesh) and explicitly configured.
type Disabled struct{}

// Authenticate implements Authenticator.
func (Disabled) Authenticate(*http.Request) (string, error) { return "anonymous", nil }

type apiKey struct {
	name string
	hash [sha256.Size]byte
}

// StaticKeys authenticates "Authorization: Bearer <key>" against a fixed
// set of API keys using constant-time comparison.
type StaticKeys struct {
	keys []apiKey
}

// ParseStaticKeys parses a comma-separated list of "name:key" or "key"
// entries. Unnamed keys are identified as key-1, key-2, ...
func ParseStaticKeys(spec string) (*StaticKeys, error) {
	s := &StaticKeys{}
	seen := map[string]bool{}
	for i, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, key := fmt.Sprintf("key-%d", i+1), raw
		if n, k, ok := strings.Cut(raw, ":"); ok {
			name, key = strings.TrimSpace(n), strings.TrimSpace(k)
		}
		if name == "" || key == "" {
			return nil, fmt.Errorf("api key entry %d is malformed", i+1)
		}
		if len(key) < 16 {
			return nil, fmt.Errorf("api key %q is too short (minimum 16 characters)", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate api key name %q", name)
		}
		seen[name] = true
		s.keys = append(s.keys, apiKey{name: name, hash: sha256.Sum256([]byte(key))})
	}
	if len(s.keys) == 0 {
		return nil, errors.New("no api keys configured")
	}
	return s, nil
}

// Authenticate implements Authenticator.
func (s *StaticKeys) Authenticate(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", ErrUnauthenticated
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(token)))
	caller := ""
	// Compare against every key so timing does not reveal which matched.
	for _, k := range s.keys {
		if subtle.ConstantTimeCompare(got[:], k.hash[:]) == 1 && caller == "" {
			caller = k.name
		}
	}
	if caller == "" {
		return "", ErrUnauthenticated
	}
	return caller, nil
}
