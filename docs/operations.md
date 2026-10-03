# Operations

## Resilience

Jev is the only dependency. The service protects itself, and its callers,
from a slow or failing Jev in two ways:

* **Concurrency limit.**
  * At most `JEV_MAX_CONCURRENCY` Jev calls run at once per instance.
  * Extra calls wait up to `JEV_QUEUE_TIMEOUT` for a free slot.
  * If no slot frees up, the call fails fast with `FAILED` /
    `JEV_UNAVAILABLE` instead of piling up goroutines and connections.
* **Circuit breaker.**
  * The breaker opens after `JEV_CIRCUIT_BREAKER_THRESHOLD` consecutive Jev
    failures: timeouts, connection errors, 5xx, 429, 401/403/404, or
    invalid responses.
  * While it is open, calls fail immediately with `FAILED` /
    `JEV_UNAVAILABLE` instead of each waiting `JEV_TIMEOUT`.
  * After `JEV_CIRCUIT_BREAKER_OPEN_TIMEOUT`, a probe request either closes
    the breaker or reopens it.
  * Request-specific rejections (400, 413, 422) and caller cancellations do
    **not** count. Otherwise a single caller sending bad content could cut
    off every other caller.

Rejections are always `FAILED`, never `BLOCKED`. The service does not
retry, because retries amplify load on a struggling dependency. Retries
and fail-open or fail-closed behaviour belong to the caller.

## Metrics

Prometheus metrics are served on `GUARDRAIL_METRICS_ADDR` at `/metrics`,
separately from the API port. Every label value comes from a bounded set,
so caller input cannot create unbounded series.

| Metric | Labels |
|--------|--------|
| `guardrail_http_requests_total`, `guardrail_http_request_duration_seconds` | `route` (mux pattern or `unmatched`), `method`, `code` |
| `guardrail_judgments_total` | `judgment`, `reason_code`, `policy_id` |
| `guardrail_findings_total` | `category`, `policy_id` |
| `guardrail_jev_requests_total`, `guardrail_jev_request_duration_seconds` | `outcome`: `success`, `timeout`, `unavailable`, `error`, `canceled`, `rejected_circuit_open` or `rejected_concurrency_limit` |
| `guardrail_jev_in_flight_requests` | none |
| `guardrail_jev_circuit_breaker_state`, `guardrail_jev_circuit_breaker_transitions_total` | `state` / `to` |
| `guardrail_policies_loaded`, `guardrail_draining`, `guardrail_build_info` | none, except `version` and `commit` on `build_info` |

Go runtime and process metrics are also exported. Suggested alerts are in
[`deploy/kubernetes/README.md`](../deploy/kubernetes/README.md).

## Logging

All logs use `log/slog` and are JSON by default. Every request-scoped line
carries `request_id`, and `client_id` when one was supplied. Guard requests
also carry `caller` and `policy_id`. The completion log records `judgment`,
`reason_code` and `matched_findings`. **Request content is never logged.**

## Shutdown and readiness

* **Graceful shutdown.** On SIGTERM the instance shuts down in this order:
  1. `/ready` returns 503 (`draining`) immediately.
  2. The instance keeps serving for `GUARDRAIL_SHUTDOWN_DELAY`, so load
     balancers stop routing to it.
  3. It stops accepting new connections and drains in-flight requests for
     up to `GUARDRAIL_SHUTDOWN_TIMEOUT`.

  A second signal skips the delay.
* **Readiness and Jev.** With `GUARDRAIL_READY_CHECK_JEV=true` (the
  default, per the original spec), a Jev outage makes every replica unready
  at once. Callers then get connection errors instead of `FAILED`
  judgments. The Kubernetes manifests therefore set it to `false`.
* **Deployment.** Kubernetes manifests are in
  [`deploy/kubernetes`](../deploy/kubernetes). The container image is
  distroless and runs as non-root, and the manifests set a read-only root
  filesystem.
* **Version.** `guardrail -version` prints the version. It is also exposed
  as `guardrail_build_info`.

## Release process

* **CI** (`.github/workflows/ci.yml`) runs on every push and pull request:
  * a `go mod tidy` check, gofmt, vet and race tests with coverage
  * golangci-lint
  * govulncheck
  * Kubernetes manifest schema validation and image-pin checks
  * an image build plus an end-to-end container smoke test
    (`scripts/smoke-test.sh`)
* **Release** (`.github/workflows/release.yml`) runs when a `vX.Y.Z` tag is
  pushed:
  * re-runs the verification
  * builds `linux/amd64` and `linux/arm64` images
  * pushes them to `ghcr.io/alpkeskin/jev-guardrail` with an SBOM and
    max-mode provenance attestations, tagged `X.Y.Z`, `X.Y`, `X` and
    `latest` (pre-releases get only `X.Y.Z`)
  * signs them keylessly with cosign
  * creates a GitHub release with generated notes, standalone binaries
    (linux, macOS, windows; bundled with `policies/`) and `checksums.txt`
* All third-party actions are pinned to commit SHAs. Dependabot keeps Go
  modules, actions and base images up to date.
* `make check` runs the CI checks locally. `make smoke` builds the image
  and runs the smoke test.
