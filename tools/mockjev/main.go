// Command mockjev is a DEVELOPMENT-ONLY stand-in for TypeSafe's System One
// API (POST /v1/systemone) that answers the Noul questions asked by
// internal/jev with trivial keyword scoring.
// It is used for local development and CI smoke tests. Never deploy it.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"
)

type request struct {
	State struct {
		Content string `json:"content"`
	} `json:"state"`
	Model     string                     `json:"model"`
	Questions map[string]json.RawMessage `json:"questions"`
}

type answer struct {
	Type string  `json:"type"`
	Noul float64 `json:"noul"`
}

var keywords = map[string][]string{
	"prompt_injection":      {"ignore all previous", "ignore previous instructions", "disregard your instructions"},
	"jailbreak":             {"developer mode", "do anything now", "no restrictions"},
	"system_prompt_leak":    {"system prompt", "your instructions verbatim"},
	"secret_exfiltration":   {"api key", "password", "sk-live"},
	"sensitive_data":        {"ssn", "credit card", "social security"},
	"malicious_instruction": {"build a bomb", "make malware"},
	"malicious_url":         {"http://malware.", "phishing"},
	"unsafe_content":        {"unsafe-test-marker"},
}

func main() {
	addr := flag.String("addr", ":8000", "listen address")
	apiKey := flag.String("api-key", "", "required Authorization bearer key (empty disables the check)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /v1/systemone", func(w http.ResponseWriter, r *http.Request) {
		if *apiKey != "" && r.Header.Get("Authorization") != "Bearer "+*apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil ||
			req.Model == "" || len(req.Questions) == 0 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		input := strings.ToLower(req.State.Content)
		out := struct {
			Model   string            `json:"model"`
			Answers map[string]answer `json:"answers"`
		}{Model: "mockjev", Answers: map[string]answer{}}
		for id := range req.Questions {
			p := 0.02
			for _, kw := range keywords[id] {
				if strings.Contains(input, kw) {
					p = 0.97
					break
				}
			}
			out.Answers[id] = answer{Type: "noul", Noul: p}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("mockjev (development only) listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
