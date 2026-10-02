package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

func TestRequestID(t *testing.T) {
	tests := []struct {
		name, header string
		keep         bool
	}{
		{"provided", "req_123", true},
		{"missing", "", false},
		{"malformed", "bad id\nwith newline", false},
		{"too long", strings.Repeat("a", 129), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))
			var ctxID string
			h := RequestID(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctxID = reqctx.RequestID(r.Context())
				reqctx.LoggerFromContext(r.Context()).Info("inside")
			}))
			r := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				r.Header.Set(HeaderRequestID, tc.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if tc.keep && ctxID != tc.header {
				t.Fatalf("ctx id = %q, want %q", ctxID, tc.header)
			}
			if !tc.keep && (!strings.HasPrefix(ctxID, "req_") || ctxID == tc.header) {
				t.Fatalf("expected generated id, got %q", ctxID)
			}
			if w.Header().Get(HeaderRequestID) != ctxID {
				t.Fatalf("response header = %q, ctx = %q", w.Header().Get(HeaderRequestID), ctxID)
			}
			for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				var m map[string]any
				_ = json.Unmarshal([]byte(line), &m)
				if m["request_id"] != ctxID {
					t.Fatalf("log line missing request_id: %s", line)
				}
			}
		})
	}
}

func TestNewRequestIDUnique(t *testing.T) {
	a, b := NewRequestID(), NewRequestID()
	if a == b {
		t.Fatal("request ids must be unique")
	}
}

type staticResolver struct{}

func (staticResolver) Resolve(id string) (guardrail.Policy, bool) {
	if id == "acme" {
		return guardrail.Policy{ClientID: "acme"}, true
	}
	return guardrail.Policy{ClientID: "default"}, false
}

func TestClientIDAndPolicyResolution(t *testing.T) {
	tests := []struct{ header, wantClient, wantPolicy string }{
		{"", "", "default"},
		{"acme", "acme", "acme"},
		{"unknown", "unknown", "default"},
		{"../../etc/passwd", "", "default"},
	}
	for _, tc := range tests {
		var gotClient, gotPolicy string
		h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotClient = reqctx.ClientID(r.Context())
			p, _ := reqctx.PolicyFromContext(r.Context())
			gotPolicy = p.ClientID
		}), ClientID, ResolvePolicy(staticResolver{}))
		r := httptest.NewRequest("POST", "/v1/guard", nil)
		r.Header.Set(HeaderClientID, tc.header)
		h.ServeHTTP(httptest.NewRecorder(), r)
		if gotClient != tc.wantClient || gotPolicy != tc.wantPolicy {
			t.Errorf("header %q: client=%q policy=%q", tc.header, gotClient, gotPolicy)
		}
	}
}

func TestRecover(t *testing.T) {
	h := Recover(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(599) })(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 599 {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestRecoverAfterResponseStartedAborts(t *testing.T) {
	called := false
	h := Recover(func(http.ResponseWriter, *http.Request) { called = true })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("partial"))
			panic("boom")
		}))
	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler { //nolint:errorlint // panic values are compared by identity
			t.Fatalf("recover = %v, want http.ErrAbortHandler", rec)
		}
		if called {
			t.Fatal("onPanic must not write a second response")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}
