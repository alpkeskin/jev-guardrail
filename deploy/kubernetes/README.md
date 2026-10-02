# Kubernetes deployment

Kustomize manifests for running Jev Guardrail in production.

```text
base/                      Deployment, Service, PDB, HPA, NetworkPolicy, ServiceAccount,
                           config and policy ConfigMaps
components/servicemonitor  Optional Prometheus Operator ServiceMonitor
overlays/production        Example overlay: namespace, pinned image, Jev URL, client policies
```

## Before the first deploy

1. **Create the secret.** It is deliberately not part of the manifests, so
   keys never end up in Git. Prefer your secret manager (for example
   External Secrets or Vault). The equivalent `kubectl` command is:

   ```bash
   kubectl -n jev-guardrail create secret generic jev-guardrail-secrets \
     --from-literal=jev-api-key='<jev api key>' \
     --from-file=gateway-api-keys=./gateway-api-keys   # one "name:key" per line
   ```

   Both values are mounted as files. The service reads them via
   `JEV_API_KEY_FILE` and `GUARDRAIL_API_KEYS_FILE`, and fails to start if
   either is missing or empty.

2. **Pin the image** in your overlay, preferably by digest:
   `images: [{name: ghcr.io/alpkeskin/jev-guardrail, digest: sha256:...}]`.
   `make k8s-validate` rejects unpinned and `:latest` images.

3. **Set `JEV_URL`** and add client policies in your overlay. Use
   `behavior: merge` on the `jev-guardrail-policies` ConfigMap, as the
   example does. `default.yaml` comes from the base.

4. **Restrict the NetworkPolicy** sources to your actual callers (for
   example the LiteLLM namespace) and your monitoring namespace.

```bash
kustomize build deploy/kubernetes/overlays/production | kubectl apply -f -
```

## Operational notes

- **Rollouts and shutdown.**
  - Rollouts use `maxUnavailable: 0`.
  - On SIGTERM, `/ready` immediately returns 503 (`draining`). The pod
    keeps serving for `GUARDRAIL_SHUTDOWN_DELAY` (10s) while endpoints
    converge, then drains in-flight requests for up to
    `GUARDRAIL_SHUTDOWN_TIMEOUT` (20s).
  - `terminationGracePeriodSeconds` (40s) must exceed the sum of these
    two values.
- **Readiness does not depend on Jev** (`GUARDRAIL_READY_CHECK_JEV=false`).
  If Jev is down, every replica would otherwise become unready at the same
  time. Callers would then get connection errors instead of structured
  `FAILED` / `JEV_UNAVAILABLE` judgments. Watch Jev health through metrics
  and the circuit breaker instead.
- **Policy changes require a rollout.** The ConfigMap name carries a
  content hash, so changing a policy triggers a rolling restart. Invalid
  policies make new pods fail at startup, and because of
  `maxUnavailable: 0` the old pods keep serving.
- **Runtime limits.** `GOMAXPROCS` and `GOMEMLIMIT` are derived from the
  container limits. Adjust `GOMEMLIMIT` whenever you change
  `limits.memory`.
- **Metrics** are on port 9090 (`/metrics`), separate from the API port.

### Suggested alerts

| Alert | Expression (sketch) |
|---|---|
| Circuit breaker open | `max(guardrail_jev_circuit_breaker_state{state="open"}) == 1` for 1m |
| High FAILED rate | `sum(rate(guardrail_judgments_total{judgment="FAILED"}[5m])) / sum(rate(guardrail_judgments_total[5m])) > 0.05` |
| Jev latency | `histogram_quantile(0.99, sum by (le) (rate(guardrail_jev_request_duration_seconds_bucket[5m]))) > 2` |
| Concurrency saturation | `sum(rate(guardrail_jev_requests_total{outcome="rejected_concurrency_limit"}[5m])) > 0` |
| Elevated 5xx | `sum(rate(guardrail_http_requests_total{code=~"5.."}[5m])) > 0` |
