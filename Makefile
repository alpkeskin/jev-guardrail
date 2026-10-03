BINARY  := bin/guardrail
IMAGE   ?= jev-guardrail:dev
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

KUSTOMIZE          ?= kustomize
KUBECONFORM        ?= kubeconform
KUBERNETES_VERSION ?= 1.31.0
K8S_OVERLAYS       := deploy/kubernetes/overlays/production
CRD_SCHEMAS        := https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json

.PHONY: all build test test-unit test-integration race cover vet fmt fmt-check lint vuln \
        run mockjev docker smoke k8s-render k8s-validate check clean

all: check build

## check: everything CI runs, except the container image
check: fmt-check vet lint race k8s-validate

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/guardrail

test:
	go test ./...

test-unit:
	go test ./internal/...

test-integration:
	go test ./tests/integration/...

race:
	go test -race -count=1 ./...

cover:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

lint:
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

run: build
	./$(BINARY)

## mockjev: development-only Jev stand-in on :8000
mockjev:
	go run ./tests/mockjev -addr :8000

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

## smoke: build the image and smoke-test it end to end
smoke: docker
	scripts/smoke-test.sh $(IMAGE)

k8s-render:
	@for o in $(K8S_OVERLAYS); do $(KUSTOMIZE) build $$o; done

## k8s-validate: schema-validate rendered manifests and require pinned images
k8s-validate:
	@set -e; for o in $(K8S_OVERLAYS); do \
	  echo "validating $$o"; \
	  out="$$($(KUSTOMIZE) build $$o)"; \
	  echo "$$out" | $(KUBECONFORM) -strict -summary -kubernetes-version $(KUBERNETES_VERSION) \
	    -schema-location default -schema-location '$(CRD_SCHEMAS)'; \
	  if echo "$$out" | grep -E '^\s+image:' | grep -vE ':[^/]+$$|@sha256:' ; then \
	    echo "error: unpinned image (tag or digest required)"; exit 1; fi; \
	  if echo "$$out" | grep -E '^\s+image:.*:latest$$'; then \
	    echo "error: :latest image"; exit 1; fi; \
	done

clean:
	rm -rf bin coverage.out
