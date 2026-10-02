package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/alpkeskin/jev-guardrail/internal/guardrail"
)

// GuardRequest is the body of POST /v1/guard. Unknown fields are accepted
// and ignored so callers can send future metadata.
type GuardRequest struct {
	Content     *string `json:"content"`
	ContentType string  `json:"content_type,omitempty"`
	// Type is accepted as an alias of ContentType.
	Type string `json:"type,omitempty"`
}

// requestError is a request validation failure.
type requestError struct {
	code   guardrail.ReasonCode
	status int
	err    error
}

func (e *requestError) Error() string { return e.err.Error() }

func invalid(format string, args ...any) *requestError {
	return &requestError{code: guardrail.ReasonInvalidRequest, status: http.StatusBadRequest, err: fmt.Errorf(format, args...)}
}

// decodeGuardRequest reads and validates the request body.
func decodeGuardRequest(w http.ResponseWriter, r *http.Request, maxBytes int64) (guardrail.EvaluationInput, *requestError) {
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(body)

	var req GuardRequest
	if err := dec.Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return guardrail.EvaluationInput{}, &requestError{
				code: guardrail.ReasonInvalidRequest, status: http.StatusRequestEntityTooLarge,
				err: fmt.Errorf("request body exceeds %d bytes", maxBytes),
			}
		}
		return guardrail.EvaluationInput{}, invalid("malformed JSON body: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return guardrail.EvaluationInput{}, invalid("request body must contain a single JSON object")
	}

	if req.Content == nil {
		return guardrail.EvaluationInput{}, invalid("content is required")
	}
	if *req.Content == "" {
		return guardrail.EvaluationInput{}, invalid("content must not be empty")
	}
	if !utf8.ValidString(*req.Content) {
		return guardrail.EvaluationInput{}, &requestError{
			code: guardrail.ReasonUnsupportedContent, status: http.StatusBadRequest,
			err: errors.New("content must be valid UTF-8"),
		}
	}

	ct := req.ContentType
	if req.Type != "" {
		if ct != "" && ct != req.Type {
			return guardrail.EvaluationInput{}, invalid("type and content_type disagree")
		}
		ct = req.Type
	}
	contentType := guardrail.DefaultContentType
	if ct != "" {
		contentType = guardrail.ContentType(ct)
		if !contentType.Valid() {
			return guardrail.EvaluationInput{}, &requestError{
				code: guardrail.ReasonUnsupportedContent, status: http.StatusBadRequest,
				err: fmt.Errorf("unsupported content_type %q", ct),
			}
		}
	}
	return guardrail.EvaluationInput{Content: *req.Content, ContentType: contentType}, nil
}
