# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/guardrail ./cmd/guardrail

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/guardrail /app/guardrail
COPY policies /app/policies
ENV GUARDRAIL_ADDR=:8080 \
    GUARDRAIL_POLICY_DIR=/app/policies
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/guardrail"]
