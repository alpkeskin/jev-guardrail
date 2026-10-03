# API reference

The machine-readable contract is [`internal/api/openapi.yaml`](../internal/api/openapi.yaml), also served at `GET /openapi.yaml`.

## `POST /v1/guard`

| Header          | Required | Purpose |
|-----------------|----------|---------|
| `Authorization` | yes*     | `Bearer <gateway-api-key>`. Answers *who is calling*. |
| `X-Client-ID`   | no       | Selects the policy. **Not** authentication. Missing, unknown or malformed values use the default policy. |
| `X-Request-ID`  | no       | Correlation ID (`[A-Za-z0-9._:-]{1,128}`). It is generated when missing or malformed and echoed back in the response header and body. |

\* Unless authentication is explicitly disabled.

Request body:

```json
{ "content": "...", "content_type": "prompt" }
```

* `content` (required, non-empty, UTF-8) is the text to inspect. Callers
  extract the text themselves; this API does not accept LLM request formats
  such as `model` or `messages`.
* `content_type` (optional, default `text`) is one of `prompt`, `response`,
  `tool_input`, `tool_output`, `document` or `text`. `type` is accepted as
  an alias.
* Unknown fields are ignored, so callers can send future metadata.

Response body:

| Field        | Description |
|--------------|-------------|
| `judgment`   | `PASSED`, `BLOCKED` or `FAILED`. |
| `reason`     | `{code, message}`. It is the primary reason for `BLOCKED` and `FAILED` and is omitted for `PASSED`. **Base decisions on `code`, not on `message`.** |
| `findings`   | Matched findings, sorted by score. It is `[]` when nothing matched and is omitted for `FAILED`. |
| `request_id` | The request ID. |

A finding *matches* when its category has an enabled rule and its score is
at or above the rule's threshold. Only matched findings are returned. A
matched `review` rule appears in `findings` but does not cause `BLOCKED`.

#### Judgment semantics and status codes

| Judgment  | Meaning | HTTP |
|-----------|---------|------|
| `PASSED`  | Evaluation completed and no blocking rule was violated. | 200 |
| `BLOCKED` | Evaluation completed and at least one `block` rule was violated. | 200 |
| `FAILED`  | Evaluation could not be completed reliably. **This is not evidence that the content is malicious.** | 400 / 413 / 500 / 502 / 503 |

A security finding is not a transport error, so `BLOCKED` is always `200`.
Failure codes map to HTTP status as follows:

| `reason.code`         | HTTP | When |
|-----------------------|------|------|
| `INVALID_REQUEST`     | 400 (413 if the body is too large) | Malformed JSON, or missing or empty `content` |
| `UNSUPPORTED_CONTENT` | 400  | Unknown `content_type`, or content that is not valid UTF-8 |
| `JEV_TIMEOUT`         | 503  | Jev did not answer within `JEV_TIMEOUT`, or Jev returned 408/504 |
| `JEV_UNAVAILABLE`     | 503  | Connection failure, or Jev returned 502/503/429 |
| `JEV_ERROR`           | 502  | Any other Jev error status, an invalid response, or a requested detector with no result |
| `INVALID_POLICY`      | 500  | No policy could be resolved |
| `INTERNAL_ERROR`      | 500  | An unexpected error or a recovered panic |

The service never turns a failure into `BLOCKED` and never reports `PASSED`
when evaluation failed. **Fail-open versus fail-closed is the caller's
decision.**

Authentication failures return `401` with
`{"error":{"code":"UNAUTHORIZED",...},"request_id":...}`. This is not a
judgment, because no evaluation was attempted.

## `GET /health`, `GET /ready` and `GET /openapi.yaml`

These endpoints are unauthenticated and never run an evaluation.

* `/health` returns 200 while the process is alive. It stays 200 while the
  instance is draining.
* `/ready` reports whether policies are loaded and, when
  `GUARDRAIL_READY_CHECK_JEV=true`, whether Jev's health endpoint
  responds. It returns 200 `{"status":"ready"}`, or 503 with
  `{"status":"not_ready"}` or `{"status":"draining"}`.
* `/openapi.yaml` serves the OpenAPI 3.1 contract
  ([`internal/api/openapi.yaml`](../internal/api/openapi.yaml)).
