BINARY ?= hankoshell-operator
VERSION ?= $(shell python3 scripts/versions.py get release version)
GOOS ?= linux
GOARCH ?= amd64
CONTROLLER_GEN ?= controller-gen
CONTROLLER_GEN_VERSION := $(shell python3 scripts/versions.py get tools controller_gen)
GOLANGCI_LINT_VERSION := $(shell python3 scripts/versions.py get tools golangci_lint)
LINT_BUILD_TAGS ?=
GOLANGCI_LINT := $(CURDIR)/.tools/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell go env GOVERSION)/golangci-lint
GO_ARCH_LINT_VERSION := $(shell python3 scripts/versions.py get tools go_arch_lint)
GOVULNCHECK_VERSION := $(shell python3 scripts/versions.py get tools govulncheck)
CHART := charts/hankoshell-operator
KUBERNETES_VERSION ?= $(shell python3 scripts/versions.py get kubernetes default)
KEYCLOAK_VERSION ?= $(shell python3 scripts/versions.py get keycloak default)
RELEASE_VERSION := $(shell python3 scripts/versions.py get release version)

.DEFAULT_GOAL := all

.PHONY: versions-sync all check preflight fmt-check generate manifests generated-check build vet test chart-test integration-test keycloak-integration-test lint arch vuln install-preflight-tools install-tools release-dry-run system-test workload-identity-probe workload-installed-test
versions-sync:
	python3 scripts/versions.py sync

all: check build
check: fmt-check vet test chart-test
preflight: fmt-check vet generated-check
	python3 -m unittest discover -s scripts -p 'test_*.py'

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
	python3 $(CHART)/tests/workload-binding.py
integration-test:
	@assets="$$(bash scripts/install-envtest.sh $(KUBERNETES_VERSION))" && \
		KUBEBUILDER_ASSETS="$$assets" KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		go test -tags=integration -race -count=1 -timeout=5m -v ./api/v1alpha1
keycloak-integration-test:
	# Budget the complete serial provider and recovery matrices; request/startup deadlines remain bounded.
	KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) go test -tags=keycloak_integration -race -count=1 -timeout=25m -v ./internal/controller
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
install-preflight-tools:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
install-tools: install-preflight-tools $(GOLANGCI_LINT)
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

# Native capability qualification only; no new operator production API is installed.
workload-identity-probe:
	python3 scripts/workload-identity-probe.py --keycloak-version $(KEYCLOAK_VERSION) \
		--kubernetes-version $(KUBERNETES_VERSION) --output "$(WORKLOAD_OUTPUT)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --openssl "$(OPENSSL)"

# Additive installed qualification; deep migration uses the reviewed matrix entry.
workload-installed-test:
	python3 scripts/workload-installed-test.py --keycloak-version $(KEYCLOAK_VERSION) \
		--kubernetes-version $(KUBERNETES_VERSION) $(if $(filter $(shell python3 scripts/versions.py get kubernetes deep_migration),$(KUBERNETES_VERSION)),--deep-migration) \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(DIGEST)" --revision "$(REVISION)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --openssl "$(OPENSSL)" --helm "$$(command -v helm)" \
		--oras "$(ORAS)" --output "$(WORKLOAD_OUTPUT)"
