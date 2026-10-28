ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.23@sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=1.1.0
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
    -ldflags "-X github.com/Alien6-Studio/hankoshell-operator/internal/version.Agent=${VERSION}" \
    -o /hankoshell-operator ./cmd/operator

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.23@sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201 AS cosign
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /cosign-source
# Public module downloads retain checksum-database verification. Recompile the
# reviewed release with the supported Go runtime and patched verification SDKs.
# Keep the same reviewed modules as the native verifier.
COPY tools/bootstrap/cosign_pins.sh /cosign_pins.sh
COPY tools/bootstrap/verifier-evidence/main.go /verifier-evidence.go
RUN . /cosign_pins.sh \
    && go mod init hankoshell.local/cosign-build \
    && go get "github.com/sigstore/cosign/v3/cmd/cosign@$COSIGN_VERSION" \
    && go get $COSIGN_DEPENDENCIES \
    && test "$(go list -m -f '{{.Version}}' github.com/sigstore/cosign/v3)" = "$COSIGN_VERSION" \
    && packages="$(CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go list -deps github.com/sigstore/cosign/v3/cmd/cosign)" \
    && ! printf '%s\n' "$packages" | grep -E '^golang.org/x/crypto/openpgp(/|$)' > /dev/null \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
        -ldflags "-s -w -X sigs.k8s.io/release-utils/version.gitVersion=$COSIGN_VERSION" \
        -o /cosign github.com/sigstore/cosign/v3/cmd/cosign \
    && printf '%s\n' "$packages" | go run /verifier-evidence.go \
        --binary /cosign --version "$COSIGN_VERSION" > /verifier-evidence.json

FROM gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY --from=builder /hankoshell-operator /hankoshell-operator
COPY --from=cosign /cosign /usr/local/bin/cosign
COPY --from=cosign /verifier-evidence.json /usr/share/hankoshell-operator/verifier-evidence.json
COPY LICENSE NOTICE THIRD_PARTY_NOTICES THIRD_PARTY_NOTICES.cosign /usr/share/licenses/hankoshell-operator/
USER 65534
ENTRYPOINT ["/hankoshell-operator"]
