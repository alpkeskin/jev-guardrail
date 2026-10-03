package api

import (
	"encoding/json"
	"net/http"

	reqctx "github.com/alpkeskin/jev-guardrail/internal/context"
	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// GuardResponse is the body returned by POST /v1/guard.
type GuardResponse struct {
	Judgment guardrail.Decision `json:"judgment"`
	Reason   *guardrail.Reason  `json:"reason,omitempty"`
	// Findings is always present ([] when empty) for PASSED and BLOCKED
	// and omitted for FAILED.
	Findings  []guardrail.Finding `json:"findings,omitzero"`
	RequestID string              `json:"request_id"`
}

// ErrorResponse is returned for non-judgment errors (e.g. 401).
type ErrorResponse struct {
	Error     ErrorBody `json:"error"`
	RequestID string    `json:"request_id"`
}

// ErrorBody describes a transport-level error.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newGuardResponse(j guardrail.Judgment, requestID string) GuardResponse {
	resp := GuardResponse{Judgment: j.Decision, Reason: j.Reason, RequestID: requestID}
	if j.Decision != guardrail.Failed {
		resp.Findings = j.Findings
		if resp.Findings == nil {
			resp.Findings = []guardrail.Finding{}
		}
	}
	return resp
}

// statusFor maps a judgment to an HTTP status. Security judgments are
// never transport failures.
func statusFor(j guardrail.Judgment) int {
	if j.Decision != guardrail.Failed {
		return http.StatusOK
	}
	if j.Reason == nil {
		return http.StatusInternalServerError
	}
	switch j.Reason.Code {
	case guardrail.ReasonInvalidRequest, guardrail.ReasonUnsupportedContent:
		return http.StatusBadRequest
	case guardrail.ReasonJevTimeout, guardrail.ReasonJevUnavailable:
		return http.StatusServiceUnavailable
	case guardrail.ReasonJevError:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJudgment(w http.ResponseWriter, r *http.Request, status int, j guardrail.Judgment) {
	writeJSON(w, status, newGuardResponse(j, reqctx.RequestID(r.Context())))
}

// WriteInternalFailure writes a FAILED/INTERNAL_ERROR judgment (used for
// recovered panics).
func WriteInternalFailure(w http.ResponseWriter, r *http.Request) {
	writeJudgment(w, r, http.StatusInternalServerError, guardrail.FailedJudgment(guardrail.ReasonInternalError))
}

// WriteUnauthorized writes a 401 error. Authentication failures are not
// judgments: no evaluation was attempted.
func WriteUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="jev-guardrail"`)
	writeJSON(w, http.StatusUnauthorized, ErrorResponse{
		Error:     ErrorBody{Code: "UNAUTHORIZED", Message: "Missing or invalid credentials."},
		RequestID: reqctx.RequestID(r.Context()),
	})
}
