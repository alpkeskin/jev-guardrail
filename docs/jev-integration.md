# Jev integration

All Jev specifics live in `internal/jev`:

* `client.go` handles HTTP transport, timeouts and error classification.
* `evaluator.go` implements `guardrail.Evaluator`.
* `mapper.go` holds the single table that maps taxonomy categories to Jev
  detector names.

The adapter assumes this wire contract. If Jev's real API differs, only
this package changes.

```http
POST {JEV_URL}/v1/evaluate
Authorization: Bearer {JEV_API_KEY}        # header and scheme are configurable
X-Request-ID: req_123

{"input": "...", "input_type": "prompt",
 "detectors": ["prompt_injection", "system_prompt_leakage"],
 "metadata": {"request_id": "req_123", "policy_id": "acme-production"}}
```

```json
{"results": [{"detector": "prompt_injection", "score": 0.94, "explanation": "..."}]}
```

| Category | Jev detector |
|---|---|
| `PROMPT_INJECTION` | `prompt_injection` |
| `JAILBREAK` | `jailbreak` |
| `SYSTEM_PROMPT_LEAK` | `system_prompt_leakage` |
| `SECRET_EXFILTRATION` | `secret_leakage` |
| `SENSITIVE_DATA` | `pii` |
| `MALICIOUS_INSTRUCTION` | `harmful_instructions` |
| `MALICIOUS_URL` | `malicious_url` |
| `UNSAFE_CONTENT` | `unsafe_content` |

The adapter applies these rules to Jev's response:

* Scores must be in [0, 1].
* Every requested detector must return a result. Otherwise that category
  was never evaluated, and the result is `JEV_ERROR` rather than an
  unreliable `PASSED`.
* Unknown detectors are dropped.
* Redirects from Jev are never followed. A 3xx response is treated as
  `JEV_ERROR`.
* Explanations are never exposed or logged.

## Extending

`guardrail.Evaluator` is the detection seam:

```go
type Evaluator interface {
    Evaluate(ctx context.Context, input EvaluationInput, policy Policy) (Evaluation, error)
}
```

Regex, DLP, URL-reputation or custom classifiers can implement it without
any API change. `guardrail.PolicyEngine` (the default is `ThresholdEngine`)
owns the decision, and `auth.Authenticator` owns caller identity.
`guardrail.MockEvaluator` provides deterministic `PASSED`, `BLOCKED` and
`FAILED` scenarios for tests.
