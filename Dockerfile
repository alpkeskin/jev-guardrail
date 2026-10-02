# syntax=docker/dockerfile:1

# Base images are overridable so builds can use an internal registry mirror.
ARG GO_IMAGE=golang:1.24-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# Cross-compile on the build platform for fast multi-arch builds.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/guardrail ./cmd/guardrail

# Distroless static: no shell or package manager, runs as non-root (65532).
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="jev-guardrail" \
      org.opencontainers.image.description="LLM-agnostic AI guardrail decision API" \
      org.opencontainers.image.source="https://github.com/alpkeskin/jev-guardrail" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
WORKDIR /app
COPY --from=build /out/guardrail /app/guardrail
COPY policies /app/policies
ENV GUARDRAIL_ADDR=:8080 \
    GUARDRAIL_METRICS_ADDR=:9090 \
    GUARDRAIL_POLICY_DIR=/app/policies
EXPOSE 8080 9090
USER 65532:65532
ENTRYPOINT ["/app/guardrail"]
