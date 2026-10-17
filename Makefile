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
GOTESTSUM_VERSION := $(shell python3 scripts/versions.py get tools gotestsum)
GOTESTSUM := $(CURDIR)/.tools/gotestsum-$(GOTESTSUM_VERSION)/gotestsum
GO_LICENSES_VERSION := $(shell python3 scripts/versions.py get tools go_licenses)
GO_LICENSES := $(CURDIR)/.tools/go-licenses-$(GO_LICENSES_VERSION)-$(shell GOTOOLCHAIN=local go env GOVERSION)/go-licenses
TEST_REPORT_DIR ?= $(CURDIR)/.tools/test-results
PRE_COMMIT_HOME ?= $(CURDIR)/.tools/pre-commit-cache
KEYCLOAK_SHARD ?= all
KEYCLOAK_STABILITY_ROOT ?=
KEYCLOAK_STABILITY_OUTPUT ?= $(TEST_REPORT_DIR)/keycloak-stability-$(KEYCLOAK_STABILITY_ROOT)
SCALE_PROFILE ?= smoke
SCALE_WORKERS ?= 4
SCALE_SECONDS ?=
CHART := charts/hankoshell-operator
KUBERNETES_VERSION ?= $(shell python3 scripts/versions.py get kubernetes default)
KEYCLOAK_VERSION ?= $(shell python3 scripts/versions.py get keycloak default)
RELEASE_VERSION := $(shell python3 scripts/versions.py get release version)

.DEFAULT_GOAL := all

.PHONY: versions-sync all check preflight fmt-check generate manifests generated-check build vet test coverage chart-test integration-test keycloak-integration-test keycloak-stability-test authentik-integration-test security-mutations security-fuzz licenses lint arch vuln hook-tools hooks-check install-hook-tools install-preflight-tools install-tools release-dry-run system-test workload-identity-probe workload-installed-test fleet-installed-test portable-installed-test scale-installed-test
versions-sync:
	python3 scripts/versions.py sync

all: check build
check: fmt-check vet test chart-test coverage
preflight: fmt-check vet generated-check
	python3 scripts/public-contract.py check
	python3 scripts/stable-contract.py
	python3 scripts/security-surface.py check
	python3 scripts/compatibility-gate.py check
	python3 scripts/go-api-contract.py check
	python3 scripts/compatibility-evidence.py check
	python3 -m unittest discover -s scripts -p 'test_*.py'

fmt-check:
	@test -z "$$(gofmt -l $$(find api cmd internal scripts -name '*.go'))" || { gofmt -l $$(find api cmd internal scripts -name '*.go'); exit 1; }
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
test: $(GOTESTSUM)
	python3 scripts/go-tests.py unit --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/unit"
coverage: test
	python3 scripts/check-coverage.py --profile "$(TEST_REPORT_DIR)/unit/coverage.out"
security-mutations:
	python3 scripts/security-mutations.py $(if $(MUTATION_OUTPUT),--output "$(MUTATION_OUTPUT)")
security-fuzz:
	python3 scripts/security-fuzz.py $(if $(FUZZ_SECONDS),--seconds "$(FUZZ_SECONDS)") $(if $(FUZZ_OUTPUT),--output "$(FUZZ_OUTPUT)")
chart-test:
	helm lint $(CHART) --kube-version $(KUBERNETES_VERSION) --set-string image.tag=lint
	bash $(CHART)/tests/image-verification.sh
	bash $(CHART)/tests/cluster-identity.sh
	python3 $(CHART)/tests/fleet-plan.py
	bash $(CHART)/tests/network-policy.sh
	python3 $(CHART)/tests/keycloak-transport.py
	python3 $(CHART)/tests/observability.py
	python3 $(CHART)/tests/concurrency.py
	python3 $(CHART)/tests/organization-projection.py
	python3 $(CHART)/tests/experimental-provider.py
	python3 $(CHART)/tests/lifecycle.py
	python3 $(CHART)/tests/kubernetes-compatibility.py
	python3 $(CHART)/tests/workload-binding.py
integration-test: $(GOTESTSUM)
	@assets="$$(bash scripts/install-envtest.sh $(KUBERNETES_VERSION))" && \
		KUBEBUILDER_ASSETS="$$assets" KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		python3 scripts/go-tests.py kubernetes --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/kubernetes-$(KUBERNETES_VERSION)"
keycloak-integration-test: $(GOTESTSUM)
	KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) python3 scripts/go-tests.py keycloak --shard "$(KEYCLOAK_SHARD)" \
		--gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/keycloak-$(KEYCLOAK_VERSION)-$(KEYCLOAK_SHARD)"
keycloak-stability-test: $(GOTESTSUM)
	KEYCLOAK_VERSION=26.7.5 python3 scripts/keycloak-stability.py --root "$(KEYCLOAK_STABILITY_ROOT)" \
		--gotestsum "$(GOTESTSUM)" --output "$(KEYCLOAK_STABILITY_OUTPUT)"
authentik-integration-test: $(GOTESTSUM)
	python3 scripts/authentik-fixture.py --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/authentik-2026.8.4"

$(GOTESTSUM):
	@mkdir -p "$(@D)"
	GOBIN="$(@D)" go install gotest.tools/gotestsum@$(GOTESTSUM_VERSION)
$(GOLANGCI_LINT):
	@mkdir -p "$(@D)"
	GOBIN="$(@D)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
# The classifier must be compiled by the toolchain that resolves the modules,
# or it cannot recognize standard-library packages.
$(GO_LICENSES):
	@mkdir -p "$(@D)"
	GOBIN="$(@D)" GOTOOLCHAIN=local go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)
licenses: $(GO_LICENSES)
	python3 scripts/check-licenses.py --go-licenses "$(GO_LICENSES)"
	git diff --exit-code -- THIRD_PARTY_NOTICES THIRD_PARTY_NOTICES.cosign
lint: $(GOLANGCI_LINT)
	@actual="$$('$(GOLANGCI_LINT)' --version | awk '{print $$4}')"; \
		test "$$actual" = "$(patsubst v%,%,$(GOLANGCI_LINT_VERSION))" || \
		{ echo "Expected golangci-lint $(GOLANGCI_LINT_VERSION), got $$actual" >&2; exit 1; }
	"$(GOLANGCI_LINT)" run --build-tags=$(LINT_BUILD_TAGS) --timeout 5m ./...
arch:
	go-arch-lint check
vuln:
	govulncheck ./...
hook-tools:
	python3 scripts/install-hook-tools.py "$(CURDIR)/.tools/hook-tools"
hooks-check: hook-tools
	PRE_COMMIT_HOME="$(PRE_COMMIT_HOME)" python3 .tools/hook-tools/pre-commit.pyz run --all-files --show-diff-on-failure
install-hook-tools: hook-tools
	go install github.com/fe3dback/go-arch-lint@$(GO_ARCH_LINT_VERSION)
install-preflight-tools:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)
install-tools: install-preflight-tools $(GOLANGCI_LINT) $(GOTESTSUM) $(GO_LICENSES) hook-tools
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

# Uses an already scanned immutable archive; never publishes a registry artifact.
fleet-installed-test:
	python3 scripts/fleet-installed-test.py --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" --keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" --kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)" --output "$(FLEET_OUTPUT)"

# Both pinned providers use the same reviewed intent corpus on an installed chart.
portable-installed-test:
	python3 scripts/portable-installed-test.py --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" --keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" --kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)" --output "$(PORTABLE_OUTPUT)"

# Fresh report directory only. Soak requires >=86400 measured steady seconds.
scale-installed-test:
	python3 scripts/scale-installed-test.py --profile "$(SCALE_PROFILE)" --workers "$(SCALE_WORKERS)" $(if $(SCALE_SECONDS),--seconds "$(SCALE_SECONDS)") \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" \
		--keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)" --output "$(SCALE_OUTPUT)"

.PHONY: recovery-installed-test
recovery-installed-test:
	python3 scripts/recovery-installed-test.py \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" \
		--keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" \
		--output "$(RECOVERY_OUTPUT)" --kind "$(KIND)" --kubectl "$(KUBECTL)" \
		--helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)"

.PHONY: transactions-installed-test
transactions-installed-test:
	python3 scripts/transactions-installed-test.py \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" \
		--keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" \
		--output "$(TRANSACTIONS_OUTPUT)" --kind "$(KIND)" --kubectl "$(KUBECTL)" \
		--helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)"
