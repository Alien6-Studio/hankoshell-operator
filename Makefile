BINARY ?= hankoshell-operator
VERSION ?= dev
GOOS ?= linux
GOARCH ?= amd64
CONTROLLER_GEN ?= controller-gen
CONTROLLER_GEN_VERSION := v0.21.0
GOLANGCI_LINT_VERSION := v2.14.0
LINT_BUILD_TAGS ?=
GOLANGCI_LINT := $(CURDIR)/.tools/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell go env GOVERSION)/golangci-lint
GO_ARCH_LINT_VERSION := v1.19.0
GOVULNCHECK_VERSION := v1.8.0
CHART := charts/hankoshell-operator
KUBERNETES_VERSION ?= 1.37.0
KEYCLOAK_VERSION ?= 26.8.0
RELEASE_VERSION := 0.3.0

.PHONY: all check fmt-check generate manifests generated-check build vet test chart-test integration-test keycloak-integration-test lint arch vuln install-tools release-dry-run system-test
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
	helm lint $(CHART) --kube-version $(KUBERNETES_VERSION) --set-string image.tag=lint
	bash $(CHART)/tests/image-verification.sh
	bash $(CHART)/tests/cluster-identity.sh
	bash $(CHART)/tests/network-policy.sh
	python3 $(CHART)/tests/keycloak-transport.py
	python3 $(CHART)/tests/observability.py
	python3 $(CHART)/tests/organization-projection.py
	python3 $(CHART)/tests/kubernetes-compatibility.py
integration-test:
	@assets="$$(bash scripts/install-envtest.sh $(KUBERNETES_VERSION))" && \
		KUBEBUILDER_ASSETS="$$assets" KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		go test -tags=integration -race -count=1 -timeout=5m -v ./api/v1alpha1
keycloak-integration-test:
	KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) go test -tags=keycloak_integration -race -count=1 -timeout=8m -v ./internal/controller
$(GOLANGCI_LINT):
	@mkdir -p "$(@D)"
	GOBIN="$(@D)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
lint: $(GOLANGCI_LINT)
	@actual="$$('$(GOLANGCI_LINT)' --version | awk '{print $$4}')"; \
		test "$$actual" = "$(patsubst v%,%,$(GOLANGCI_LINT_VERSION))" || \
		{ echo "Expected golangci-lint $(GOLANGCI_LINT_VERSION), got $$actual" >&2; exit 1; }
	"$(GOLANGCI_LINT)" run --build-tags=$(LINT_BUILD_TAGS) --timeout 5m ./...
arch:
	go-arch-lint check
vuln:
	govulncheck ./...
install-tools: $(GOLANGCI_LINT)
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
	go install github.com/fe3dback/go-arch-lint@$(GO_ARCH_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

# Inputs must be the archive, digest and fresh evidence from the OCI security job.
# COSIGN/ATTEST/OPENSSL are paths to the pinned tools and OpenSSL 3.
release-dry-run:
	python3 scripts/release-dry-run.py --version $(RELEASE_VERSION) --revision "$(REVISION)" \
		--digest "$(DIGEST)" --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" \
		--output "$(DRY_RUN_OUTPUT)" --helm "$$(command -v helm)" \
		--cosign "$(COSIGN)" --attest "$(ATTEST)" --openssl "$(OPENSSL)" --oras "$(ORAS)"

system-test:
	python3 scripts/system-test.py --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" \
		--digest "$(DIGEST)" --revision "$(REVISION)" --output "$(SYSTEM_OUTPUT)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$$(command -v helm)" \
		--oras "$(ORAS)" --openssl "$(OPENSSL)"
