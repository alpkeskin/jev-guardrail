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

const maxResponseBytes = 1 << 20

// ClientConfig configures the Jev HTTP client.
type ClientConfig struct {
	BaseURL      string
	APIKey       string
	Timeout      time.Duration
	EvaluatePath string
	// HealthPath is used for readiness checks; empty disables them.
	HealthPath string
	HTTPClient *http.Client
}

// Client talks to Jev over HTTP. All errors it returns are
// *guardrail.EvaluationError classified as JEV_TIMEOUT, JEV_UNAVAILABLE,
// JEV_ERROR or INTERNAL_ERROR.
type Client struct {
	base       *url.URL
	apiKey     string
	timeout    time.Duration
	evalPath   string
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
	if cfg.EvaluatePath == "" {
		cfg.EvaluatePath = "/v1/evaluate"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 2 * time.Second,
		}}
	}
	return &Client{
		base:       u,
		apiKey:     cfg.APIKey,
		timeout:    cfg.Timeout,
		evalPath:   cfg.EvaluatePath,
		healthPath: cfg.HealthPath,
		http:       hc,
	}, nil
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.base.String(), "/") + "/" + strings.TrimLeft(path, "/")
}

// Evaluate sends an evaluation request to Jev. The request ID from ctx is
// forwarded in the X-Request-ID header.
func (c *Client) Evaluate(ctx context.Context, req EvaluateRequest) (EvaluateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return EvaluateResponse{}, guardrail.NewEvaluationError(guardrail.ReasonInternalError, err)
	}

	tctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(tctx, http.MethodPost, c.endpoint(c.evalPath), bytes.NewReader(body))
	if err != nil {
		return EvaluateResponse{}, guardrail.NewEvaluationError(guardrail.ReasonInternalError, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	c.setCommonHeaders(ctx, httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return EvaluateResponse{}, c.classifyTransportError(ctx, tctx, err)
	}
	defer resp.Body.Close()

	if err := classifyStatus(resp.StatusCode); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return EvaluateResponse{}, err
	}

	var out EvaluateResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := dec.Decode(&out); err != nil {
		if tctx.Err() != nil {
			return EvaluateResponse{}, c.classifyTransportError(ctx, tctx, err)
		}
		return EvaluateResponse{}, guardrail.NewEvaluationError(guardrail.ReasonJevError, fmt.Errorf("decode response: %w", err))
	}
	if out.Results == nil {
		return EvaluateResponse{}, guardrail.NewEvaluationError(guardrail.ReasonJevError, errors.New("response has no results field"))
	}
	return out, nil
}

// Ping checks Jev's health endpoint. It never runs an evaluation.
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
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
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

func classifyStatus(code int) error {
	switch {
	case code >= 200 && code <= 299:
		return nil
	case code == http.StatusGatewayTimeout || code == http.StatusRequestTimeout:
		return guardrail.NewEvaluationError(guardrail.ReasonJevTimeout, fmt.Errorf("jev returned HTTP %d", code))
	case code == http.StatusServiceUnavailable || code == http.StatusBadGateway || code == http.StatusTooManyRequests:
		return guardrail.NewEvaluationError(guardrail.ReasonJevUnavailable, fmt.Errorf("jev returned HTTP %d", code))
	default:
		return guardrail.NewEvaluationError(guardrail.ReasonJevError, fmt.Errorf("jev returned HTTP %d", code))
	}
}
