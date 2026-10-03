#!/usr/bin/env bash
# Runs the benchmark end to end: builds the image, starts the guardrail
# against TypeSafe, replays the corpus, then writes the report.
#
#   JEV_API_KEY=<typesafe key> benchmark/run.sh
#
# Settings (environment variables):
#   RUN          run name; results go to benchmark/results/$RUN. Reusing a
#                name resumes that run (default: timestamp)
#   RPS          offered load in requests/s (default 40; TypeSafe allows
#                80 requests/s per account)
#   CONCURRENCY  max requests in flight (default 64)
#   LIMIT        only send the first N samples (default 0 = all)
#   JEV_MODEL    model to benchmark (default jev-1.13.0)
#   POLICY       policy the report evaluates (default benchmark/policies/eval-all.yaml)
#   IMAGE        image tag (default jev-guardrail:dev); SKIP_BUILD=1 reuses it
#   JEV_URL      override the Jev endpoint, e.g. a local mockjev for a
#                dry run of the tooling (http://host.docker.internal:8000)
#
# Requires: docker, go, curl.
set -euo pipefail

cd "$(dirname "$0")/.."
: "${JEV_API_KEY:?set JEV_API_KEY to a TypeSafe API key}"
RUN="${RUN:-$(date +%Y%m%d-%H%M%S)}"
RPS="${RPS:-40}"
CONCURRENCY="${CONCURRENCY:-64}"
LIMIT="${LIMIT:-0}"
JEV_MODEL="${JEV_MODEL:-jev-1.13.0}"
POLICY="${POLICY:-benchmark/policies/eval-all.yaml}"
IMAGE="${IMAGE:-jev-guardrail:dev}"
DATA=benchmark/data/samples.jsonl
OUT="benchmark/results/$RUN"
NAME="jev-guardrail-bench-$$"
API=127.0.0.1:18080
METRICS=127.0.0.1:19090
export CGO_ENABLED=0

[ -f "$DATA" ] || { echo "missing $DATA; run: uv run benchmark/datasets/prepare.py" >&2; exit 1; }
mkdir -p "$OUT/policies"

if [ -z "${SKIP_BUILD:-}" ]; then
  make docker IMAGE="$IMAGE" >/dev/null 2>&1
fi

# The shipped policies plus the score-reporting benchmark policy.
cp policies/*.yaml benchmark/policies/benchmark.yaml "$OUT/policies/"
chmod 755 "$OUT/policies" && chmod 644 "$OUT/policies"/*.yaml

GW_KEY="bench-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
cleanup() {
  docker logs "$NAME" >"$OUT/guardrail.log" 2>&1 || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# JEV_API_KEY is passed by name so the key never appears in process args.
docker run -d --name "$NAME" -p "$API:8080" -p "$METRICS:9090" \
  -v "$PWD/$OUT/policies:/app/policies:ro" \
  -e JEV_API_KEY -e JEV_MODEL="$JEV_MODEL" ${JEV_URL:+-e JEV_URL="$JEV_URL"} \
  -e GUARDRAIL_API_KEYS="bench:$GW_KEY" \
  -e GUARDRAIL_LOG_LEVEL=warn \
  -e JEV_MAX_CONCURRENCY="$CONCURRENCY" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "http://$API/ready" 2>/dev/null && break
  sleep 0.2
done
curl -fsS -o /dev/null "http://$API/ready" || { echo "guardrail did not become ready" >&2; exit 1; }

cat >"$OUT/meta.json" <<EOF
{
  "run": "$RUN",
  "started": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)$(git diff --quiet 2>/dev/null || echo -dirty)",
  "image": "$IMAGE",
  "jev_model": "$JEV_MODEL",
  "jev_url": "${JEV_URL:-https://api.typesafe.ai}",
  "rps": $RPS,
  "concurrency": $CONCURRENCY,
  "limit": $LIMIT,
  "corpus_sha256": "$(shasum -a 256 "$DATA" | cut -d' ' -f1)"
}
EOF

GUARDRAIL_API_KEY="$GW_KEY" go run ./benchmark/cmd/loadgen \
  -data "$DATA" -out "$OUT/results.jsonl" -url "http://$API" \
  -rps "$RPS" -concurrency "$CONCURRENCY" -limit "$LIMIT" -resume

curl -fsS "http://$METRICS/metrics" >"$OUT/metrics.txt" || true
go run ./benchmark/cmd/report -data "$DATA" -results "$OUT/results.jsonl" -policy "$POLICY"
echo "report: $OUT/report.md"
