BINARY := bin/guardrail
IMAGE  ?= jev-guardrail:latest

.PHONY: all build test test-unit test-integration race vet fmt fmt-check run docker clean

all: fmt-check vet test build

build:
	CGO_ENABLED=0 go build -trimpath -o $(BINARY) ./cmd/guardrail

test:
	go test ./...

test-unit:
	go test ./internal/...

test-integration:
	go test ./tests/integration/...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

run: build
	./$(BINARY)

docker:
	docker build -t $(IMAGE) .

clean:
	rm -rf bin
