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
ARG VERSION=1.0.0
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
RUN . /cosign_pins.sh \
    && go mod init hankoshell.local/cosign-build \
    && go get "github.com/sigstore/cosign/v3/cmd/cosign@$COSIGN_VERSION" \
    && go get $COSIGN_DEPENDENCIES \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
        -ldflags "-s -w -X sigs.k8s.io/release-utils/version.gitVersion=$COSIGN_VERSION" \
        -o /cosign github.com/sigstore/cosign/v3/cmd/cosign

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /hankoshell-operator /hankoshell-operator
COPY --from=cosign /cosign /usr/local/bin/cosign
COPY LICENSE NOTICE THIRD_PARTY_NOTICES THIRD_PARTY_NOTICES.cosign /usr/share/licenses/hankoshell-operator/
USER 65534
ENTRYPOINT ["/hankoshell-operator"]
