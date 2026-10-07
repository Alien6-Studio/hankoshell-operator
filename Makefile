BINARY ?= hankoshell-operator
VERSION ?= dev
GOOS ?= linux
GOARCH ?= amd64
CONTROLLER_GEN ?= controller-gen
CONTROLLER_GEN_VERSION := v0.21.0
GOLANGCI_LINT_VERSION := v2.12.2
GOLANGCI_LINT := $(CURDIR)/.tools/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell go env GOVERSION)/golangci-lint
GO_ARCH_LINT_VERSION := v1.19.0
GOVULNCHECK_VERSION := v1.1.4
CHART := charts/hankoshell-operator

.PHONY: all check fmt-check generate manifests generated-check build vet test chart-test lint arch vuln install-tools
all: check build
check: fmt-check vet test chart-test

fmt-check:
	@test -z "$$(gofmt -l $$(find api cmd internal -name '*.go'))" || { gofmt -l $$(find api cmd internal -name '*.go'); exit 1; }
generate:
	@test "$$($(CONTROLLER_GEN) --version)" = "Version: $(CONTROLLER_GEN_VERSION)"
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/..."
manifests:
	@test "$$($(CONTROLLER_GEN) --version)" = "Version: $(CONTROLLER_GEN_VERSION)"
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=$(CHART)/crds
generated-check: generate manifests
	git diff --exit-code -- api $(CHART)/crds
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath \
		-ldflags "-X github.com/Alien6-Studio/hankoshell-operator/internal/version.Agent=$(VERSION)" \
		-o /tmp/$(BINARY)-$(GOOS)-$(GOARCH) ./cmd/operator
vet:
	go vet ./...
test:
	go test -race -count=1 ./...
chart-test:
	helm lint $(CHART) --set-string image.tag=lint
	bash $(CHART)/tests/image-verification.sh
	bash $(CHART)/tests/cluster-identity.sh
	bash $(CHART)/tests/network-policy.sh
$(GOLANGCI_LINT):
	@mkdir -p "$(@D)"
	GOBIN="$(@D)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
lint: $(GOLANGCI_LINT)
	@actual="$$('$(GOLANGCI_LINT)' --version | awk '{print $$4}')"; \
		test "$$actual" = "$(patsubst v%,%,$(GOLANGCI_LINT_VERSION))" || \
		{ echo "Expected golangci-lint $(GOLANGCI_LINT_VERSION), got $$actual" >&2; exit 1; }
	"$(GOLANGCI_LINT)" run --timeout 5m ./...
arch:
	go-arch-lint check
vuln:
	govulncheck ./...
install-tools: $(GOLANGCI_LINT)
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
	go install github.com/fe3dback/go-arch-lint@$(GO_ARCH_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
