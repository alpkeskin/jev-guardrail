// Command mockjev is a DEVELOPMENT-ONLY stand-in for Jev that implements
// the wire contract assumed by internal/jev with trivial keyword scoring.
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
	Input     string   `json:"input"`
	Detectors []string `json:"detectors"`
}

type result struct {
	Detector string  `json:"detector"`
	Score    float64 `json:"score"`
}

var keywords = map[string][]string{
	"prompt_injection":      {"ignore all previous", "ignore previous instructions", "disregard your instructions"},
	"jailbreak":             {"developer mode", "do anything now", "no restrictions"},
	"system_prompt_leakage": {"system prompt", "your instructions verbatim"},
	"secret_leakage":        {"api key", "password", "sk-live"},
	"pii":                   {"ssn", "credit card", "social security"},
	"harmful_instructions":  {"build a bomb", "make malware"},
	"malicious_url":         {"http://malware.", "phishing"},
	"unsafe_content":        {"unsafe-test-marker"},
}

func main() {
	addr := flag.String("addr", ":8000", "listen address")
	apiKey := flag.String("api-key", "", "required Authorization bearer key (empty disables the check)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if *apiKey != "" && r.Header.Get("Authorization") != "Bearer "+*apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		input := strings.ToLower(req.Input)
		out := struct {
			Results []result `json:"results"`
		}{Results: []result{}}
		for _, d := range req.Detectors {
			score := 0.02
			for _, kw := range keywords[d] {
				if strings.Contains(input, kw) {
					score = 0.97
					break
				}
			}
			out.Results = append(out.Results, result{Detector: d, Score: score})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("mockjev (development only) listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
