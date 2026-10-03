# Configuration

All configuration comes from environment variables. Invalid or ambiguous
configuration fails startup. Every `*_FILE` variable reads its value from a
file, such as a mounted Kubernetes secret.

**Server**

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDRAIL_ADDR` | `:8080` | API listen address |
| `GUARDRAIL_METRICS_ADDR` | `:9090` | Prometheus `/metrics` listen address (`-` disables it). Must differ from the API address. |
| `GUARDRAIL_POLICY_DIR` | `policies` | Policy directory |
| `GUARDRAIL_MAX_BODY_BYTES` | `1048576` | Maximum request body size |
| `GUARDRAIL_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `GUARDRAIL_LOG_FORMAT` | `json` | `json` or `text` |
| `GUARDRAIL_READY_CHECK_JEV` | `true` | Include the Jev health check in `/ready` (see [Operations](operations.md#shutdown-and-readiness)) |
| `GUARDRAIL_SHUTDOWN_DELAY` | `5s` | How long the instance keeps serving with `/ready`=503 after SIGTERM, before closing listeners |
| `GUARDRAIL_SHUTDOWN_TIMEOUT` | `15s` | Maximum time to drain in-flight requests |

**Caller authentication**

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDRAIL_API_KEYS` | none | Comma-separated `name:key` or `key` entries (min. 16 characters, no whitespace) |
| `GUARDRAIL_API_KEYS_FILE` | none | One `name:key` per line, merged with the above. Blank lines and `#` comments are ignored. |
| `GUARDRAIL_AUTH_DISABLED` | `false` | Must be set explicitly to run without API keys. Conflicts with configured keys. |

**Jev**

| Variable | Default | Description |
|----------|---------|-------------|
| `JEV_URL` | `https://api.typesafe.ai` | TypeSafe API base URL |
| `JEV_API_KEY` / `JEV_API_KEY_FILE` | **required** (exactly one) | TypeSafe API key |
| `JEV_MODEL` | `jev-latest` | Jev model. Pin a version such as `jev-1.13.0` in production |
| `JEV_AUTH_HEADER` | `Authorization` | Header that carries the key, for example `X-API-Key` |
| `JEV_AUTH_SCHEME` | `Bearer` for `Authorization`, otherwise empty | Prefix for the key (`-` sends the bare key) |
| `JEV_TIMEOUT` | `5s` | Per-evaluation timeout |
| `JEV_EVALUATE_PATH` | `/v1/systemone` | System One endpoint |
| `JEV_HEALTH_PATH` | empty (disabled) | Jev health endpoint used by readiness. TypeSafe documents none |
| `JEV_MAX_CONCURRENCY` | `100` | Maximum concurrent Jev calls per instance. Also caps Jev connections. |
| `JEV_QUEUE_TIMEOUT` | `250ms` | Maximum wait for a free slot before failing fast (`0` means no waiting) |
| `JEV_CIRCUIT_BREAKER_THRESHOLD` | `5` | Consecutive Jev failures that open the breaker (`0` disables it) |
| `JEV_CIRCUIT_BREAKER_OPEN_TIMEOUT` | `15s` | How long the breaker stays open before probing |
| `JEV_CIRCUIT_BREAKER_HALF_OPEN_REQUESTS` | `1` | Concurrent probe requests while half-open |
