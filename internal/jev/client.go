package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

const (
	maxResponseBytes   = 1 << 20
	healthConnHeadroom = 2
)

// Defaults for TypeSafe's hosted System One API.
const (
	DefaultAuthHeader   = "Authorization"
	DefaultEvaluatePath = "/v1/systemone"
	DefaultModel        = "jev-latest"
)

// statusOverloaded is TypeSafe's non-standard "529 Overloaded" status.
const statusOverloaded = 529

// ClientConfig configures the Jev HTTP client.
type ClientConfig struct {
	BaseURL string
	// APIKey is required. It is sent as "<AuthHeader>: <AuthScheme> <APIKey>"
	// (or just the key when AuthScheme is empty).
	APIKey string
	// AuthHeader defaults to "Authorization".
	AuthHeader string
	// AuthScheme is e.g. "Bearer". Empty sends the bare key.
	AuthScheme   string
	Timeout      time.Duration
	EvaluatePath string
	// Model is the Jev model sent with every request (default
	// "jev-latest"). Pin a version such as "jev-1.13.0" in production so
	// scores do not shift under fixed policy thresholds.
	Model string
	// HealthPath is used for readiness checks; empty disables them.
	HealthPath string
	// MaxConns caps connections to Jev (default 100). Align it with the
	// concurrency limit so requests never queue inside the transport.
	MaxConns   int
	HTTPClient *http.Client
}

// Client talks to Jev over HTTP. All errors it returns are
// *guardrail.EvaluationError classified as JEV_TIMEOUT, JEV_UNAVAILABLE,
// JEV_ERROR or INTERNAL_ERROR.
type Client struct {
	base       *url.URL
	authHeader string
	authValue  string
	timeout    time.Duration
	evalPath   string
	model      string
	healthPath string
	http       *http.Client
}

// NewClient validates cfg and returns a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid Jev base URL %q", cfg.BaseURL)
	}
	if cfg.Timeout <= 0 {
		return nil, errors.New("jev timeout must be positive")
	}
	if cfg.AuthHeader == "" {
		cfg.AuthHeader = DefaultAuthHeader
	}
	if !validHeaderName(cfg.AuthHeader) {
		return nil, fmt.Errorf("invalid jev auth header name %q", cfg.AuthHeader)
	}
	switch http.CanonicalHeaderKey(cfg.AuthHeader) {
	case "Host", "Content-Type", "Content-Length", "Accept", "X-Request-Id", "Transfer-Encoding", "Connection":
		return nil, fmt.Errorf("jev auth header %q is reserved", cfg.AuthHeader)
	}
	if cfg.APIKey == "" {
		return nil, errors.New("jev api key is required")
	}
	if !validHeaderToken(cfg.APIKey) {
		return nil, errors.New("jev api key must not contain whitespace or control characters")
	}
	if cfg.AuthScheme != "" && !validHeaderName(cfg.AuthScheme) {
		return nil, fmt.Errorf("invalid jev auth scheme %q", cfg.AuthScheme)
	}
	authValue := cfg.APIKey
	if cfg.AuthScheme != "" {
		authValue = cfg.AuthScheme + " " + cfg.APIKey
	}
	if cfg.EvaluatePath == "" {
		cfg.EvaluatePath = DefaultEvaluatePath
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 100
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			// Never follow redirects: a redirect would resend content and
			// credentials to an endpoint that was not configured.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				MaxIdleConns:        cfg.MaxConns,
				MaxIdleConnsPerHost: cfg.MaxConns,
				// Headroom beyond the evaluation concurrency limit keeps
				// health checks from queueing behind saturated evaluations.
				MaxConnsPerHost:     cfg.MaxConns + healthConnHeadroom,
				ForceAttemptHTTP2:   true,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
			}}
	}
	return &Client{
		base:       u,
		authHeader: http.CanonicalHeaderKey(cfg.AuthHeader),
		authValue:  authValue,
		timeout:    cfg.Timeout,
		evalPath:   cfg.EvaluatePath,
		model:      cfg.Model,
		healthPath: cfg.HealthPath,
		http:       hc,
	}, nil
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.base.String(), "/") + "/" + strings.TrimLeft(path, "/")
}

// Evaluate sends a System One request to Jev using the configured model.
// The request ID from ctx is forwarded in the X-Request-ID header.
func (c *Client) Evaluate(ctx context.Context, req SystemOneRequest) (SystemOneResponse, error) {
	req.Model = c.model
	body, err := json.Marshal(req)
	if err != nil {
		return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonInternalError, err)
	}

	tctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(tctx, http.MethodPost, c.endpoint(c.evalPath), bytes.NewReader(body))
	if err != nil {
		return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonInternalError, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	c.setCommonHeaders(ctx, httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return SystemOneResponse{}, c.classifyTransportError(ctx, tctx, err)
	}
	defer func() {
		// Drain so the keep-alive connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if err := classifyStatus(resp.StatusCode); err != nil {
		return SystemOneResponse{}, err
	}

	var out SystemOneResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := dec.Decode(&out); err != nil {
		if tctx.Err() != nil {
			return SystemOneResponse{}, c.classifyTransportError(ctx, tctx, err)
		}
		return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonJevError, fmt.Errorf("decode response: %w", err))
	}
	if out.Answers == nil {
		return SystemOneResponse{}, guardrail.NewEvaluationError(guardrail.ReasonJevError, errors.New("response has no answers field"))
	}
	return out, nil
}

// Ping checks Jev's health endpoint. It never runs an evaluation. TypeSafe
// documents no health endpoint, so with the default configuration Ping is
// a no-op.
func (c *Client) Ping(ctx context.Context) error {
	if c.healthPath == "" {
		return nil
	}
	tctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, c.endpoint(c.healthPath), nil)
	if err != nil {
		return guardrail.NewEvaluationError(guardrail.ReasonInternalError, err)
	}
	c.setCommonHeaders(ctx, req)
	resp, err := c.http.Do(req)
	if err != nil {
		return c.classifyTransportError(ctx, tctx, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return guardrail.NewEvaluationError(guardrail.ReasonJevUnavailable, fmt.Errorf("health check returned HTTP %d", resp.StatusCode))
	}
	return nil
}

func (c *Client) setCommonHeaders(ctx context.Context, req *http.Request) {
	req.Header.Set(c.authHeader, c.authValue)
	if id := reqctx.RequestID(ctx); id != "" {
		req.Header.Set("X-Request-ID", id)
	}
}

func (c *Client) classifyTransportError(parent, tctx context.Context, err error) error {
	switch {
	case parent.Err() != nil:
		// The caller went away; this is not a Jev failure.
		return guardrail.NewEvaluationError(guardrail.ReasonInternalError, fmt.Errorf("request canceled: %w", err))
	case errors.Is(tctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return guardrail.NewEvaluationError(guardrail.ReasonJevTimeout, fmt.Errorf("jev did not respond within %s: %w", c.timeout, err))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return guardrail.NewEvaluationError(guardrail.ReasonJevTimeout, err)
	}
	return guardrail.NewEvaluationError(guardrail.ReasonJevUnavailable, err)
}

// StatusError is a non-2xx HTTP status returned by Jev.
type StatusError struct{ StatusCode int }

func (e *StatusError) Error() string { return fmt.Sprintf("jev returned HTTP %d", e.StatusCode) }

// IsRequestSpecific reports whether the status is caused by the individual
// request (e.g. 400, 413, 422) rather than by Jev's health or our
// configuration. Such errors must not trip the circuit breaker, otherwise a
// single caller sending bad content could cut off every other caller.
func (e *StatusError) IsRequestSpecific() bool {
	c := e.StatusCode
	return c >= 400 && c < 500 && c != http.StatusUnauthorized && c != http.StatusForbidden &&
		c != http.StatusNotFound && c != http.StatusRequestTimeout && c != http.StatusTooManyRequests
}

func classifyStatus(code int) error {
	se := &StatusError{StatusCode: code}
	switch {
	case code >= 200 && code <= 299:
		return nil
	case code == http.StatusGatewayTimeout || code == http.StatusRequestTimeout:
		return guardrail.NewEvaluationError(guardrail.ReasonJevTimeout, se)
	case code == http.StatusServiceUnavailable || code == http.StatusBadGateway ||
		code == http.StatusTooManyRequests || code == statusOverloaded:
		return guardrail.NewEvaluationError(guardrail.ReasonJevUnavailable, se)
	default:
		return guardrail.NewEvaluationError(guardrail.ReasonJevError, se)
	}
}

// validHeaderName reports whether s is an RFC 9110 token.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isTokenChar(r) {
			return false
		}
	}
	return true
}

func isTokenChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	default:
		return strings.ContainsRune("!#$%&'*+-.^_`|~", r)
	}
}

// validHeaderToken rejects whitespace and control characters, which would
// either break or allow injection into the header.
func validHeaderToken(s string) bool {
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r > 0x7e {
			return false
		}
	}
	return true
}
