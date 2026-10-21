BINARY ?= hankoshell-operator
VERSION ?= $(shell python3 -m tools.versions get release version)
GOOS ?= linux
GOARCH ?= amd64
CONTROLLER_GEN ?= controller-gen
CONTROLLER_GEN_VERSION := $(shell python3 -m tools.versions get tools controller_gen)
GOLANGCI_LINT_VERSION := $(shell python3 -m tools.versions get tools golangci_lint)
LINT_BUILD_TAGS ?=
GOLANGCI_LINT := $(CURDIR)/.tools/bin/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell go env GOVERSION)/golangci-lint
GO_ARCH_LINT_VERSION := $(shell python3 -m tools.versions get tools go_arch_lint)
GOVULNCHECK_VERSION := $(shell python3 -m tools.versions get tools govulncheck)
GOTESTSUM_VERSION := $(shell python3 -m tools.versions get tools gotestsum)
GOTESTSUM := $(CURDIR)/.tools/bin/gotestsum-$(GOTESTSUM_VERSION)/gotestsum
GO_LICENSES_VERSION := $(shell python3 -m tools.versions get tools go_licenses)
GO_LICENSES := $(CURDIR)/.tools/bin/go-licenses-$(GO_LICENSES_VERSION)-$(shell GOTOOLCHAIN=local go env GOVERSION)/go-licenses
TEST_REPORT_DIR ?= $(CURDIR)/.tools/runs/tests
PRE_COMMIT_HOME ?= $(CURDIR)/.tools/cache/pre-commit
KEYCLOAK_SHARD ?= all
KEYCLOAK_STABILITY_ROOT ?=
KEYCLOAK_STABILITY_OUTPUT ?= $(TEST_REPORT_DIR)/keycloak-stability-$(KEYCLOAK_STABILITY_ROOT)
SCALE_PROFILE ?= smoke
SCALE_WORKERS ?= 4
SCALE_SECONDS ?=
CHART := charts/hankoshell-operator
KUBERNETES_VERSION ?= $(shell python3 -m tools.versions get kubernetes default)
KEYCLOAK_VERSION ?= $(shell python3 -m tools.versions get keycloak default)
RELEASE_VERSION := $(shell python3 -m tools.versions get release version)

.DEFAULT_GOAL := all
.PHONY: keycloak-extension-build keycloak-extension-test
.PHONY: delegation-installed-test
.PHONY: storage-migration-installed-test

.PHONY: versions-sync all check preflight fmt-check generate manifests generated-check build vet test coverage chart-check integration-test keycloak-integration-test keycloak-stability-test authentik-integration-test security-mutations security-fuzz licenses lint arch vuln hook-tools hooks-check install-hook-tools install-preflight-tools install-tools release-dry-run system-test workload-identity-probe workload-installed-test fleet-installed-test portable-installed-test scale-installed-test
versions-sync:
	python3 -m tools.versions sync

all: check build
check: fmt-check vet chart-check coverage
preflight: fmt-check vet generated-check
	python3 -m tools.qualification.checks.stable_contract
	python3 -m tools.qualification.checks.security_surface check
	python3 -m tools.qualification.checks.compatibility_gate check
	python3 -m tools.qualification.checks.go_api_contract check
	python3 -m tools.qualification.checks.compatibility_evidence check

fmt-check:
	@test -z "$$(gofmt -l $$(find api cmd internal tools -name '*.go'))" || { gofmt -l $$(find api cmd internal tools -name '*.go'); exit 1; }
generate:
	@test "$$($(CONTROLLER_GEN) --version)" = "Version: $(CONTROLLER_GEN_VERSION)"
	$(CONTROLLER_GEN) object:headerFile="" paths="./api/..."
manifests:
	@test "$$($(CONTROLLER_GEN) --version)" = "Version: $(CONTROLLER_GEN_VERSION)"
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=$(CHART)/crds
	python3 -m tools.qualification.checks.crd_input_bounds
generated-check: generate manifests
	git diff --exit-code -- api $(CHART)/crds
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath \
		-ldflags "-X github.com/Alien6-Studio/hankoshell-operator/internal/version.Agent=$(VERSION)" \
		-o /tmp/$(BINARY)-$(GOOS)-$(GOARCH) ./cmd/operator
vet:
	go vet ./...
test: $(GOTESTSUM)
	python3 -m tools.qualification.runners.go_tests unit --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/unit"
coverage: test
	python3 -m tools.quality.check_coverage --profile "$(TEST_REPORT_DIR)/unit/coverage.out"
security-mutations:
	python3 -m tools.qualification.runners.security_mutations $(if $(MUTATION_OUTPUT),--output "$(MUTATION_OUTPUT)")
security-fuzz:
	python3 -m tools.qualification.runners.security_fuzz $(if $(FUZZ_SECONDS),--seconds "$(FUZZ_SECONDS)") $(if $(FUZZ_OUTPUT),--output "$(FUZZ_OUTPUT)")
storage-migration-installed-test:
	python3 -m tools.qualification.scenarios.storage_migration_installed_test --kind "$(KIND)" --kubectl "$(KUBECTL)" \
		--helm "$(HELM)" --kubernetes-version "$(KUBERNETES_VERSION)" --output "$(STORAGE_OUTPUT)" \
		$(if $(NODE_ARCHIVE),--node-archive "$(NODE_ARCHIVE)")
chart-check:
	helm lint $(CHART) --kube-version $(KUBERNETES_VERSION) --set-string image.tag=lint
	helm template qualification $(CHART) --namespace qualification --kube-version $(KUBERNETES_VERSION) --set-string image.tag=lint --include-crds > /dev/null
integration-test: $(GOTESTSUM)
	@assets="$$(bash tools/bootstrap/install_envtest.sh $(KUBERNETES_VERSION))" && \
		KUBEBUILDER_ASSETS="$$assets" KUBERNETES_VERSION=$(KUBERNETES_VERSION) \
		python3 -m tools.qualification.runners.go_tests kubernetes --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/kubernetes-$(KUBERNETES_VERSION)"
keycloak-integration-test: $(GOTESTSUM)
	KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) python3 -m tools.qualification.runners.go_tests keycloak --shard "$(KEYCLOAK_SHARD)" \
		--gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/keycloak-$(KEYCLOAK_VERSION)-$(KEYCLOAK_SHARD)"
keycloak-extension-build:
	KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) python3 -m tools.qualification.runners.keycloak_extension
keycloak-extension-test: keycloak-extension-build $(GOTESTSUM)
	KEYCLOAK_VERSION=$(KEYCLOAK_VERSION) KEYCLOAK_EXTENSION_JAR="$$(python3 -m tools.qualification.lib.keycloak_extension_source $(KEYCLOAK_VERSION))" \
		python3 -m tools.qualification.runners.go_tests keycloak-extension --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/keycloak-extension-$(KEYCLOAK_VERSION)"
keycloak-stability-test: $(GOTESTSUM)
	KEYCLOAK_VERSION=26.7.5 python3 -m tools.qualification.runners.keycloak_stability --root "$(KEYCLOAK_STABILITY_ROOT)" \
		--gotestsum "$(GOTESTSUM)" --output "$(KEYCLOAK_STABILITY_OUTPUT)"
authentik-integration-test: $(GOTESTSUM)
	python3 -m tools.qualification.fixtures.authentik_fixture --gotestsum "$(GOTESTSUM)" --output "$(TEST_REPORT_DIR)/authentik-2026.8.4"

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
	python3 -m tools.quality.check_licenses --go-licenses "$(GO_LICENSES)"
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
	python3 -m tools.bootstrap.install pre_commit gitleaks --directory "$(CURDIR)/.tools/bin/hooks"
.PHONY: staged-secrets
staged-secrets: hook-tools
	.tools/bin/hooks/gitleaks protect --staged --redact --no-banner
hooks-check: hook-tools
	PRE_COMMIT_HOME="$(PRE_COMMIT_HOME)" python3 .tools/bin/hooks/pre-commit.pyz run --all-files --show-diff-on-failure
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
	python3 -m tools.release.release_dry_run --version $(RELEASE_VERSION) --revision "$(REVISION)" \
		--digest "$(DIGEST)" --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" \
		--output "$(DRY_RUN_OUTPUT)" --helm "$$(command -v helm)" \
		--cosign "$(COSIGN)" --attest "$(ATTEST)" --openssl "$(OPENSSL)" --oras "$(ORAS)"

system-test:
	python3 -m tools.qualification.reporting.public_release_corpus capture --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" \
		--digest "$(DIGEST)" --revision "$(REVISION)" --output "$(SYSTEM_OUTPUT)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$$(command -v helm)" \
		--oras "$(ORAS)" --openssl "$(OPENSSL)"

cross-version-installed-test:
	python3 -m tools.qualification.scenarios.cross_version_installed_test \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(DIGEST)" --revision "$(REVISION)" \
		--assets "$(PREDECESSOR_ASSETS)" --trust "$(PREDECESSOR_TRUST)" --capture "$(PREDECESSOR_CAPTURE)" \
		--reviewed-corpus "$(PREDECESSOR_CORPUS)" --capture-artifact-id "$(PREDECESSOR_ARTIFACT_ID)" \
		--kubernetes-version "$(KUBERNETES_VERSION)" --keycloak-version "$(KEYCLOAK_VERSION)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$$(command -v helm)" \
		--oras "$(ORAS)" --openssl "$(OPENSSL)" --cosign "$(COSIGN)" --attest "$(ATTEST)" --output "$(COMPATIBILITY_OUTPUT)"

# Native capability qualification only; no new operator production API is installed.
workload-identity-probe:
	python3 -m tools.qualification.fixtures.workload_identity_probe --keycloak-version $(KEYCLOAK_VERSION) \
		--kubernetes-version $(KUBERNETES_VERSION) --output "$(WORKLOAD_OUTPUT)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --openssl "$(OPENSSL)"

# Additive installed qualification; deep migration uses the reviewed matrix entry.
workload-installed-test:
	python3 -m tools.qualification.scenarios.workload_installed_test --keycloak-version $(KEYCLOAK_VERSION) \
		--kubernetes-version $(KUBERNETES_VERSION) $(if $(filter $(shell python3 -m tools.versions get kubernetes deep_migration),$(KUBERNETES_VERSION)),--deep-migration) \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(DIGEST)" --revision "$(REVISION)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --openssl "$(OPENSSL)" --helm "$$(command -v helm)" \
		--oras "$(ORAS)" --output "$(WORKLOAD_OUTPUT)"

# Uses an already scanned immutable archive; never publishes a registry artifact.
delegation-installed-test:
	python3 -m tools.qualification.scenarios.delegation_installed_test --keycloak-version $(KEYCLOAK_VERSION) \
		--kubernetes-version $(KUBERNETES_VERSION) --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" \
		--digest "$(DIGEST)" --revision "$(REVISION)" --kind "$(KIND)" --kubectl "$(KUBECTL)" \
		--openssl "$(OPENSSL)" --helm "$$(command -v helm)" --oras "$(ORAS)" --output "$(DELEGATION_OUTPUT)"

# Uses an already scanned immutable archive; never publishes a registry artifact.
fleet-installed-test:
	python3 -m tools.qualification.scenarios.fleet_installed_test --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" --keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" --kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)" --output "$(FLEET_OUTPUT)"

# Both pinned providers use the same reviewed intent corpus on an installed chart.
portable-installed-test:
	python3 -m tools.qualification.scenarios.portable_installed_test --archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" --keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" --kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)" --output "$(PORTABLE_OUTPUT)"

# Fresh report directory only. Soak requires >=86400 measured steady seconds.
scale-installed-test:
	python3 -m tools.qualification.scenarios.scale_installed_test --profile "$(SCALE_PROFILE)" --workers "$(SCALE_WORKERS)" $(if $(SCALE_SECONDS),--seconds "$(SCALE_SECONDS)") \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" \
		--keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" \
		--kind "$(KIND)" --kubectl "$(KUBECTL)" --helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)" --output "$(SCALE_OUTPUT)"

.PHONY: recovery-installed-test
recovery-installed-test:
	python3 -m tools.qualification.scenarios.recovery_installed_test \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" \
		--keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" \
		--output "$(RECOVERY_OUTPUT)" --kind "$(KIND)" --kubectl "$(KUBECTL)" \
		--helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)"

.PHONY: transactions-installed-test
transactions-installed-test:
	python3 -m tools.qualification.scenarios.transactions_installed_test \
		--archive "$(OCI_ARCHIVE)" --evidence "$(OCI_EVIDENCE)" --digest "$(OCI_DIGEST)" --revision "$(REVISION)" \
		--keycloak-version "$(KEYCLOAK_VERSION)" --kubernetes-version "$(KUBERNETES_VERSION)" \
		--output "$(TRANSACTIONS_OUTPUT)" --kind "$(KIND)" --kubectl "$(KUBECTL)" \
		--helm "$(HELM)" --oras "$(ORAS)" --openssl "$(OPENSSL)"

# One entry point for existing gates; CI continues to require its full matrix.
PROFILE ?= local
QUALIFY_source := preflight chart-check arch lint
QUALIFY_unit := coverage
QUALIFY_local := preflight chart-check arch lint coverage
QUALIFY_chart := chart-check
QUALIFY_kubernetes := integration-test
QUALIFY_keycloak := keycloak-integration-test
QUALIFY_extension := keycloak-extension-test
QUALIFY_installed := system-test
QUALIFY_workload := workload-installed-test
QUALIFY_delegation := delegation-installed-test
QUALIFY_fleet := fleet-installed-test
QUALIFY_portable := portable-installed-test
QUALIFY_storage := storage-migration-installed-test
QUALIFY_scale := scale-installed-test
QUALIFY_recovery := recovery-installed-test
QUALIFY_transactions := transactions-installed-test
.PHONY: qualify qualification-help
qualify:
	$(if $(QUALIFY_$(PROFILE)),$(MAKE) $(QUALIFY_$(PROFILE)),$(error Unknown qualification profile '$(PROFILE)'; run make qualification-help))
qualification-help:
	@printf '%s\n' 'make qualify PROFILE=<profile> [existing target variables]' \
		'  local (default): source checks, chart, Go unit/race and coverage' \
		'  source | unit | chart | kubernetes | keycloak | extension' \
		'  installed | workload | delegation | fleet | portable | storage' \
		'  scale | recovery | transactions' \
		'See tools/README.md for prerequisites, immutable inputs and output paths.'
