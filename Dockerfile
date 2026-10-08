ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.23@sha256:2ac5c2a64f1f970b5120fe21c6a5e3d9190b196a9ead95797564738ecd07a8a2 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
    -ldflags "-X github.com/Alien6-Studio/hankoshell-operator/internal/version.Agent=${VERSION}" \
    -o /hankoshell-operator ./cmd/operator

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.23@sha256:2ac5c2a64f1f970b5120fe21c6a5e3d9190b196a9ead95797564738ecd07a8a2 AS cosign
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /cosign-source
# Public module downloads retain checksum-database verification. Recompile the
# reviewed release with the supported Go runtime and patched verification SDKs.
# Build the pinned main package as a versioned dependency of a small wrapper
# module, so Go buildinfo retains cosign v3.1.3 for image vulnerability matching.
RUN go mod init hankoshell.local/cosign-build \
    && go get github.com/sigstore/cosign/v3/cmd/cosign@v3.1.3 \
    && go get golang.org/x/crypto@v0.57.0 golang.org/x/mod@v0.41.0 \
        golang.org/x/net@v0.60.0 golang.org/x/text@v0.42.0 google.golang.org/grpc@v1.83.2 \
    && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath \
        -ldflags '-s -w -X sigs.k8s.io/release-utils/version.gitVersion=v3.1.3' \
        -o /cosign github.com/sigstore/cosign/v3/cmd/cosign

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder /hankoshell-operator /hankoshell-operator
COPY --from=cosign /cosign /usr/local/bin/cosign
COPY LICENSE NOTICE /usr/share/licenses/hankoshell-operator/
USER 65534
ENTRYPOINT ["/hankoshell-operator"]
